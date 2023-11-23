package eazy

import (
	"bytes"
	"io"

	"github.com/nikandfor/hacked/hfmt"
	"github.com/nikandfor/hacked/low"
	"tlog.app/go/errors"
)

type (
	// Reader is eazy decompressor.
	Reader struct {
		io.Reader

		ver int

		block []byte
		mask  int
		pos   int64 // stream position

		// current tag
		state    byte
		off, len int

		// input
		b    []byte
		i    int
		boff int64 // buffer b offset in the input stream
	}

	// Dumper is a debug printer for compressed data.
	Dumper struct {
		io.Writer

		d Reader

		GlobalOffset int64

		b low.Buf
	}
)

var eUnexpectedEOF = errors.NewNoCaller("need more")

const (
	legacy1 = "\x00\x03tlz\x00\x13000\x00\x20"
	legacy2 = "\x00\x02eazy\x00\x08"
)

// NewReader creates new decompressor reading from r.
func NewReader(r io.Reader) *Reader {
	return &Reader{
		Reader: r,
	}
}

// NewReaderBytes creates new decompressor reading from b.
// A bit more efficient NewReader(bytes.NewReader(b)).
func NewReaderBytes(b []byte) *Reader {
	return &Reader{
		b: b,
	}
}

// Reset resets the stream.
func (d *Reader) Reset(rd io.Reader) {
	d.ResetBytes(d.b[:len(d.b)])
	d.Reader = rd
}

// ResetBytes resets the stream and replaces b.
func (d *Reader) ResetBytes(b []byte) {
	d.Reader = nil
	d.b = b

	d.block = d.block[:0]
	d.pos = 0

	d.i = 0
	d.boff = 0

	d.state = 0
}

// Read is io.Reader implementation.
func (d *Reader) Read(p []byte) (n int, err error) {
	var m, i int

	for n < len(p) && err == nil {
		m, i, err = d.read(p[n:], d.i)

		n += m
		d.i = i

		if n == len(p) {
			err = nil
			break
		}

		if err != eUnexpectedEOF { //nolint:errorlint
			continue
		}

		err = d.more()
		if errors.Is(err, io.EOF) && (d.state != 0 || d.i < len(d.b)) {
			err = io.ErrUnexpectedEOF
		}
	}

	return n, err
}

func (d *Reader) read(p []byte, st int) (n, i int, err error) {
	//	defer func() { println("eazy.Decoder.read", st, i, n, err, len(d.b)) }()
	if d.state != 0 && len(d.block) == 0 {
		return 0, st, errors.New("missed meta")
	}

	i = st

	for d.state == 0 {
		i, err = d.readTag(i)
		if err != nil {
			return
		}
	}

	if d.state == 'l' && i == len(d.b) {
		return 0, i, eUnexpectedEOF
	}

	end := d.len
	if end > len(p) {
		end = len(p)
	}

	switch {
	case d.state == 'l':
		end = copy(p[:end], d.b[i:])
		i += end
	case int64(d.off+d.len) <= d.pos:
		end = copy(p[:end], d.block[d.off&d.mask:])
		d.off += end
	default:
		rlen := int(d.pos) - d.off
		if rlen == 0 {
			panic("zero run length")
		}

		for j := 0; j < rlen; {
			j += copy(p[j:rlen], d.block[(d.off+j)&d.mask:])
		}

		for j := rlen; j < end; {
			j += copy(p[j:end], p[:rlen])
		}

		d.off += end
	}

	d.len -= end

	for n < end {
		m := copy(d.block[int(d.pos)&d.mask:], p[n:end])
		n += m
		d.pos += int64(m)
	}

	if d.len == 0 {
		d.state = 0
	}

	return
}

func (d *Reader) readTag(st int) (i int, err error) {
	// skip zero padding
	for st < len(d.b) && d.b[st] == 0 {
		st++
	}

	st, err = d.checkLegacy(st)
	if err != nil {
		return st, err
	}

	tag, l, i, err := d.tag(d.b, st)
	if err != nil {
		return st, err
	}

	//	println("readTag", tag, l, st, i, d.i, len(d.b))

	if tag == Meta && l == 0 {
		return d.continueMetaTag(i)
	}

	switch tag {
	case Literal:
		d.state = 'l'
		d.len = l
	case Copy:
		d.off, i, err = d.roff(d.b, i, l)
		if err != nil {
			return st, err
		}

		d.off = int(d.pos) - d.off

		d.state = 'c'
		d.len = l
	default:
		return st, errors.New("unsupported tag: %x", tag)
	}

	return i, nil
}

func (d *Reader) continueMetaTag(st int) (i int, err error) {
	i = st
	st--

	if i == len(d.b) {
		return st, eUnexpectedEOF
	}

	meta := d.b[i]
	i++

	l, i := metaLen(d.b, i, meta)
	//	println("meta", st-1, i, meta, l, i+l, len(d.b))
	if l < 0 || i+l > len(d.b) {
		return st, eUnexpectedEOF
	}

	switch meta & MetaTagMask {
	case MetaMagic:
		if !bytes.Equal(d.b[i:i+l], []byte("eazy")) {
			return st, errors.New("bad magic")
		}
	case MetaReset:
		bs := int(d.b[i])

		d.reset(bs)
	case MetaVer:
		d.ver = int(d.b[i])
	default:
		return st, errors.New("unsupported meta: %x", meta)
	}

	i += l

	return i, nil
}

func (d *Reader) checkLegacy(st int) (int, error) {
	check := func(legacy string, st int) (int, error) {
		db := d.b[st:]

		if len(db) < len(legacy)+1 && bytes.Equal(db, []byte(legacy)[:len(db)]) { //nolint:gocritic
			return st, eUnexpectedEOF
		}

		if len(db) >= len(legacy)+1 && bytes.Equal(db[:len(legacy)], []byte(legacy)) { //nolint:gocritic
			i := len(legacy)

			bs := int(db[i])
			i++

			d.reset(bs)

			return i, nil
		}

		return st, nil
	}

	i := st

	i, err := check(legacy1, i)
	if err != nil {
		return i, err
	}

	i, err = check(legacy2, i)
	if err != nil {
		return i, err
	}

	return i, nil
}

func (d *Reader) reset(bs int) {
	bs = 1 << bs

	if cap(d.block) >= bs {
		d.block = d.block[:bs]

		for i := 0; i < bs; {
			i += copy(d.block[i:], zeros)
		}
	} else {
		d.block = make([]byte, bs)
	}

	d.pos = 0
	d.mask = bs - 1

	d.state = 0
}

func (d *Reader) tag0(b []byte, st int) (tag, l, i int, err error) {
	if st >= len(b) {
		return 0, 0, st, eUnexpectedEOF
	}

	i = st

	tag = int(b[i]) & TagMask
	l = int(b[i]) & TagLenMask
	i++

	switch l {
	case Len1:
		if i+1 > len(b) {
			return tag, l, st, eUnexpectedEOF
		}

		l = int(b[i])
		i++
	case Len2:
		if i+2 > len(b) {
			return tag, l, st, eUnexpectedEOF
		}

		l = int(b[i])<<8 | int(b[i+1])
		i += 2
	case Len4:
		if i+4 > len(b) {
			return tag, l, st, eUnexpectedEOF
		}

		l = int(b[i])<<24 | int(b[i+1])<<16 | int(b[i+2])<<8 | int(b[i+3])
		i += 4
	case Len8:
		if i+8 > len(b) {
			return tag, l, st, eUnexpectedEOF
		}

		l = int(b[i])<<56 | int(b[i+1])<<48 | int(b[i+2])<<40 | int(b[i+3])<<32 |
			int(b[i+4])<<24 | int(b[i+5])<<16 | int(b[i+6])<<8 | int(b[i+7])
		i += 8
	default:
		// l is embedded
	}

	return tag, l, i, nil
}

func (d *Reader) roff0(b []byte, st, l int) (off, i int, err error) {
	if st >= len(b) {
		return 0, st, eUnexpectedEOF
	}

	i = st

	off = int(b[i])
	i++

	switch off {
	case Off1:
		if i+1 > len(b) {
			return off, st, eUnexpectedEOF
		}

		off = int(b[i])
		i++
	case Off2:
		if i+2 > len(b) {
			return off, st, eUnexpectedEOF
		}

		off = int(b[i])<<8 | int(b[i+1])
		i += 2
	case Off4:
		if i+4 > len(b) {
			return off, st, eUnexpectedEOF
		}

		off = int(b[i])<<24 | int(b[i+1])<<16 | int(b[i+2])<<8 | int(b[i+3])
		i += 4
	case Off8:
		if i+8 > len(b) {
			return off, st, eUnexpectedEOF
		}

		off = int(b[i])<<56 | int(b[i+1])<<48 | int(b[i+2])<<40 | int(b[i+3])<<32 |
			int(b[i+4])<<24 | int(b[i+5])<<16 | int(b[i+6])<<8 | int(b[i+7])
		i += 8
	default:
		// off is embedded
	}

	off += l

	return off, i, nil
}

func (d *Reader) tag(b []byte, st int) (tag, l, i int, err error) {
	if d.ver == 0 {
		return d.tag0(b, st)
	}

	if st >= len(b) {
		return 0, 0, st, eUnexpectedEOF
	}

	i = st

	tag = int(b[i]) & TagMask
	l = int(b[i]) & TagLenMask
	i++

	switch l {
	case Len1:
		if i+1 > len(b) {
			return tag, l, st, eUnexpectedEOF
		}

		l = Len1 + int(b[i])
		i++
	case Len2:
		if i+2 > len(b) {
			return tag, l, st, eUnexpectedEOF
		}

		l = Len1 + 0xff
		l += int(b[i])<<8 | int(b[i+1])
		i += 2
	case Len4:
		if i+4 > len(b) {
			return tag, l, st, eUnexpectedEOF
		}

		l = Len1 + 0xff + 0xffff
		l += int(b[i])<<24 | int(b[i+1])<<16 | int(b[i+2])<<8 | int(b[i+3])
		i += 4
	case Len8:
		panic("too big length")
	default:
		// l is embedded
	}

	return tag, l, i, nil
}

func (d *Reader) roff(b []byte, st, l int) (off, i int, err error) {
	if d.ver == 0 {
		return d.roff0(b, st, l)
	}

	var long bool
	i = st

	if i == len(b) {
		return 0, st, eUnexpectedEOF
	}

	off = int(b[i])
	i++

	long = off == OffLong

	if long && i == len(b) {
		return 0, st, eUnexpectedEOF
	}

	if long {
		off = int(b[i])
		i++
	}

	switch off {
	case Off1:
		if i+1 > len(b) {
			return off, st, eUnexpectedEOF
		}

		off = Off1 + int(b[i])
		i++
	case Off2:
		if i+2 > len(b) {
			return off, st, eUnexpectedEOF
		}

		off = Off1 + 0xff
		off += int(b[i])<<8 | int(b[i+1])
		i += 2
	case Off4:
		if i+4 > len(b) {
			return off, st, eUnexpectedEOF
		}

		off = Off1 + 0xff + 0xffff
		off += int(b[i])<<24 | int(b[i+1])<<16 | int(b[i+2])<<8 | int(b[i+3])
		i += 4
	case Off8:
		panic("too big offset")
	default:
		// off is embedded
	}

	if !long {
		off += l
	}

	if off > len(d.block) && len(d.block) != 0 {
		panic("offset > block_size")
	}

	return off, i, nil
}

func (d *Reader) more() (err error) {
	if d.Reader == nil {
		return io.EOF
	}

	copy(d.b, d.b[d.i:])
	d.b = d.b[:len(d.b)-d.i]
	d.boff += int64(d.i)
	d.i = 0

	end := len(d.b)

	if len(d.b) == 0 {
		d.b = make([]byte, 1024)
	} else {
		d.b = append(d.b, 0, 0, 0, 0, 0, 0, 0, 0)
	}

	d.b = d.b[:cap(d.b)]

	n, err := d.Reader.Read(d.b[end:])
	//	println("more", d.i, end, end+n, n, len(d.b))
	d.b = d.b[:end+n]

	if n != 0 && errors.Is(err, io.EOF) {
		err = nil
	}

	return err
}

// Dump returns debug printed compressed buffer p.
func Dump(p []byte) string {
	var d Dumper

	_, err := d.Write(p)
	if err != nil {
		return err.Error()
	}

	_ = d.Close()

	return string(d.b)
}

// NewDumper creates new debug compressed stream printer.
func NewDumper(w io.Writer) *Dumper {
	return &Dumper{
		Writer: w,
	}
}

// Write implements io.Writer.
func (w *Dumper) Write(p []byte) (i int, err error) {
	w.b = w.b[:0]

	var tag, l int

	for i < len(p) {
		if w.GlobalOffset >= 0 {
			w.b = hfmt.Appendf(w.b, "%6x  ", int(w.GlobalOffset)+i)
		}

		w.b = hfmt.Appendf(w.b, "%4x  ", i)

		w.b = hfmt.Appendf(w.b, "%6x  ", w.d.pos)

		st := i

		for i < len(p) && p[i] == 0 {
			i++
		}

		if i != st {
			w.b = hfmt.Appendf(w.b, "pad  %4x\n", i-st)
			continue
		}

		tag, l, i, err = w.d.tag(p, i)
		if err != nil {
			return st, err
		}

		//	println("loop", i, tag>>7, l)

		switch {
		case tag == Meta && l == 0:
			if i == len(p) {
				return st, eUnexpectedEOF
			}

			meta := p[i]
			i++

			l, i = metaLen(p, i, meta)
			if l < 0 {
				return st, eUnexpectedEOF
			}

			w.b = hfmt.Appendf(w.b, "meta %2x %x  %q\n", meta>>3, l, p[i:i+l])

			if meta == MetaVer && l == 1 {
				w.d.ver = int(p[i])
			}

			i += l
		case tag == Literal:
			w.b = hfmt.Appendf(w.b, "lit  %4x        %q\n", l, p[i:i+l])

			i += l
			w.d.pos += int64(l)
		case tag == Copy:
			var off int

			off, i, err = w.d.roff(p, i, l)
			if err != nil {
				return st, err
			}

			w.d.pos += int64(l)

			w.b = hfmt.Appendf(w.b, "copy %4x  off %4x\n", l, off)
		default:
			panic(tag)
		}
	}

	w.GlobalOffset += int64(i)

	if w.Writer != nil {
		_, err = w.Writer.Write(w.b)
	}

	return i, err
}

func (w *Dumper) Close() error {
	i := 0

	if w.GlobalOffset >= 0 {
		w.b = hfmt.Appendf(w.b, "%6x  ", int(w.GlobalOffset)+i)
	}

	w.b = hfmt.Appendf(w.b, "%4x  ", i)

	w.b = hfmt.Appendf(w.b, "%6x  ", w.d.pos)

	return nil
}

func metaLen(p []byte, st int, meta byte) (l, i int) {
	i = st
	l = int(meta &^ MetaTagMask)

	if l == 7 {
		if i == len(p) {
			return -1, st
		}

		l = 7 + int(p[i])
		i++
	} else {
		l = 1 << l
	}

	return l, i
}
