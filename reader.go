package eazy

import (
	"bytes"
	stderrors "errors"
	"fmt"
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

		BlockSizeLimit      int
		RequireMagic        bool
		SkipUnsupportedMeta bool

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

var (
	eUnexpectedEOF        = errors.NewNoCaller("need more")
	ErrBadMagic           = stderrors.New("bad magic")
	ErrNoMagic            = stderrors.New("no magic")
	ErrUnsupportedVersion = stderrors.New("unsupported file format version")
	ErrUnsupportedMeta    = stderrors.New("unsupported meta tag")
	ErrOverflow           = stderrors.New("length/offset overflow")
)

const (
	legacy1 = "\x00\x03tlz\x00\x13000\x00\x20"
	legacy2 = "\x00\x02eazy\x00\x08"
)

const maxVer = 1

// NewReader creates new decompressor reading from r.
func NewReader(r io.Reader) *Reader {
	return &Reader{
		Reader:         r,
		BlockSizeLimit: 16 * MiB,
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
	d.ResetBytes(d.b[:0])
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
	//	defer func() { println("eazy.Decoder.read", st, i, n, err, d.state, d.len, len(d.b), loc.Caller(1).String()) }()
	i = st

	for d.state == 0 {
		i, err = d.readTag(i)
		if err != nil {
			return
		}
	}

	if len(d.block) == 0 {
		return 0, st, errors.New("missed meta")
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
			return 0, i, ErrOverflow
		}

		if end > rlen {
			end = rlen
		}

		for j := 0; j < end; {
			j += copy(p[j:end], d.block[(d.off+j)&d.mask:])
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
	st, err = d.checkLegacy(st)
	if err != nil {
		return st, err
	}

	// skip zero padding
	for st < len(d.b) && d.b[st] == 0 {
		st++
	}

	tag, l, i, err := d.tag(d.b, st)
	if err != nil {
		return st, err
	}

	if d.boff == 0 && st == 0 && d.b[st] != Meta && d.RequireMagic {
		return st, ErrNoMagic
	}

	//	println("readTag", tag, l, st, i, d.i, len(d.b))

	if tag == Meta && l == 0 {
		return d.continueMetaTag(i)
	}

	if d.BlockSizeLimit != 0 && l > d.BlockSizeLimit {
		return st, ErrOverflow
	}

	switch tag {
	case Literal:
		d.state = 'l'
	case Copy:
		d.off, i, err = d.roff(d.b, i, l)
		if err != nil {
			return st, err
		}

		d.off = int(d.pos) - d.off

		d.state = 'c'
	default:
		return st, errors.New("unsupported tag: %x", tag)
	}

	d.len = l

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

	if d.boff == 0 && st == 0 && meta&MetaTagMask != MetaMagic && d.RequireMagic {
		return st, ErrNoMagic
	}

	l, i, err := d.metaLen(d.b, i, meta)
	//	println("meta", st-1, i, meta, l, i+l, len(d.b))
	if err != nil {
		return st, err
	}
	if i+l > len(d.b) {
		return st, eUnexpectedEOF
	}

	switch meta & MetaTagMask {
	case MetaMagic:
		if !bytes.Equal(d.b[i:i+l], []byte("eazy")) {
			return st, ErrBadMagic
		}
	case MetaVer:
		d.ver = int(d.b[i])
		if l != 1 {
			return st, ErrOverflow
		}
		if d.ver > maxVer {
			return st, fmt.Errorf("%w: %v", ErrUnsupportedVersion, d.ver)
		}
	case MetaReset:
		bs := int(d.b[i])
		if bs > 32 || l != 1 || d.BlockSizeLimit != 0 && 1<<bs > d.BlockSizeLimit {
			return st, ErrOverflow
		}

		d.reset(bs)
	default:
		if d.SkipUnsupportedMeta {
			break
		}

		return st, fmt.Errorf("%w: %v", ErrUnsupportedMeta, meta)
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

	if bs <= cap(d.block) {
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
		return tag, l, st, ErrOverflow
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
		return off, st, ErrOverflow
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
		l += int(b[i]) | int(b[i+1])<<8
		i += 2
	case Len4:
		if i+4 > len(b) {
			return tag, l, st, eUnexpectedEOF
		}

		l = Len1 + 0xff + 0xffff
		l += int(b[i]) | int(b[i+1])<<8 | int(b[i+2])<<16 | int(b[i+3])<<24
		i += 4
	case Len8:
		return tag, l, st, ErrOverflow
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

	off, i, err = d.poff(b, i, off)
	if err != nil {
		return off, i, err
	}

	if !long {
		off += l
	}

	if off > len(d.block) && len(d.block) != 0 {
		return off, i, ErrOverflow
	}

	return off, i, nil
}

func (d *Reader) poff(b []byte, st, off int) (_, i int, err error) {
	i = st

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
		off += int(b[i]) | int(b[i+1])<<8
		i += 2
	case Off4:
		if i+4 > len(b) {
			return off, st, eUnexpectedEOF
		}

		off = Off1 + 0xff + 0xffff
		off += int(b[i]) | int(b[i+1])<<8 | int(b[i+2])<<16 | int(b[i+3])<<24
		i += 4
	case Off8:
		return off, st, ErrOverflow
	default:
		// off is embedded
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
	_ = d.Close()
	if err != nil {
		d.b = append(d.b, "\nerror: "...)
		d.b = append(d.b, err.Error()...)
	}

	return string(d.b)
}

// NewDumper creates new debug compressed stream printer.
func NewDumper(w io.Writer) *Dumper {
	return &Dumper{
		Writer: w,
	}
}

// Write implements io.Writer.
func (w *Dumper) Write(p []byte) (i int, err error) { //nolint:gocognit
	w.b = w.b[:0]

	defer func() {
		if w.Writer == nil {
			return
		}

		_, e := w.Writer.Write(w.b)
		if err == nil {
			err = e
		}
	}()

	var tag, l int

	for i < len(p) {
		if w.GlobalOffset >= 0 {
			w.b = hfmt.Appendf(w.b, "%6x  ", w.GlobalOffset+int64(i))
		}

		w.b = hfmt.Appendf(w.b, "%4x  %6x  ", i, w.d.pos)

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

			l, i, err = w.d.metaLen(p, i, meta)
			if err != nil {
				return st, err
			}

			if i+l > len(p) {
				return i, ErrOverflow
			}

			w.b = hfmt.Appendf(w.b, "meta %2x %x  %q\n", meta>>3, l, p[i:i+l])

			if meta == MetaVer && l == 1 {
				w.d.ver = int(p[i])
			}

			i += l
		case tag == Literal:
			if i+l > len(p) {
				return i, ErrOverflow
			}

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
		}
	}

	w.GlobalOffset += int64(i)

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

func (d *Reader) metaLen(b []byte, st int, meta byte) (l, i int, err error) {
	i = st
	l = int(meta &^ MetaTagMask)

	if l == MetaLenWide {
		if i == len(b) {
			return 0, st, eUnexpectedEOF
		}

		l = int(b[i])
		if l >= Off1 {
			return l, st, ErrOverflow
		}

		l += MetaLenWide
		i++
	} else {
		l = 1 << l
	}

	return l, i, nil
}
