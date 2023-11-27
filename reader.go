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
	// Parser is a low level tool to manually parse the eazy stream.
	// Use Reader to just get the data decompressed.
	Parser struct {
		Ver int
	}

	// Reader is eazy decompressor.
	Reader struct {
		io.Reader

		Parser

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

		Debug        func(ioff, ooff int64, tag byte, l, off int)
		GlobalOffset int64

		b low.Buf
	}
)

var (
	ErrEndOfBuffer        = stderrors.New("unexpected end of buffer")
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
			//	err = nil
			break
		}

		if err != ErrEndOfBuffer { //nolint:errorlint
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
		return 0, i, ErrEndOfBuffer
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
	case int64(d.off) == d.pos: // zero region
		for j := 0; j < end; {
			j += copy(p[j:end], zeros)
		}
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

	i = st

	// skip zero padding
	for i < len(d.b) && d.b[i] == 0 {
		i++
	}

	st = i

	tag, l, i, err := d.Tag(d.b, st)
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
		d.off = 0
	case Copy:
		d.off, i, err = d.Offset(d.b, i, l)
		if err != nil {
			return st, err
		}
		if d.off > len(d.block) {
			return st, ErrOverflow
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

	meta, l, i, err := d.Meta(d.b, i)
	if err != nil {
		return
	}

	if d.boff == 0 && st == 0 && meta != MetaMagic && d.RequireMagic {
		return st, ErrNoMagic
	}

	if i+l > len(d.b) {
		return st, ErrEndOfBuffer
	}

	switch meta {
	case MetaMagic:
		if !bytes.Equal(d.b[i:i+l], []byte("eazy")) {
			return st, ErrBadMagic
		}
	case MetaVer:
		d.Ver = int(d.b[i])
		if l != 1 {
			return st, ErrOverflow
		}
		if d.Ver > maxVer {
			return st, fmt.Errorf("%w: %v", ErrUnsupportedVersion, d.Ver)
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

		return st, fmt.Errorf("%w: 0x%x", ErrUnsupportedMeta, meta)
	}

	i += l

	return i, nil
}

func (d *Reader) checkLegacy(st int) (int, error) {
	check := func(legacy string, st int) (int, error) {
		db := d.b[st:]

		if len(db) < len(legacy)+1 && bytes.Equal(db, []byte(legacy)[:len(db)]) { //nolint:gocritic
			return st, ErrEndOfBuffer
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

func (d Parser) Tag0(b []byte, st int) (tag, l, i int, err error) {
	if st >= len(b) {
		return 0, 0, st, ErrEndOfBuffer
	}

	i = st

	tag = int(b[i]) & TagMask
	l = int(b[i]) & TagLenMask
	i++

	switch l {
	case Len1:
		if i+1 > len(b) {
			return tag, l, st, ErrEndOfBuffer
		}

		l = int(b[i])
		i++
	case Len2:
		if i+2 > len(b) {
			return tag, l, st, ErrEndOfBuffer
		}

		l = int(b[i])<<8 | int(b[i+1])
		i += 2
	case Len4:
		if i+4 > len(b) {
			return tag, l, st, ErrEndOfBuffer
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

func (d Parser) Offset0(b []byte, st, l int) (off, i int, err error) {
	if st >= len(b) {
		return 0, st, ErrEndOfBuffer
	}

	i = st

	off = int(b[i])
	i++

	switch off {
	case Off1:
		if i+1 > len(b) {
			return off, st, ErrEndOfBuffer
		}

		off = int(b[i])
		i++
	case Off2:
		if i+2 > len(b) {
			return off, st, ErrEndOfBuffer
		}

		off = int(b[i])<<8 | int(b[i+1])
		i += 2
	case Off4:
		if i+4 > len(b) {
			return off, st, ErrEndOfBuffer
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

func (d Parser) Tag(b []byte, st int) (tag, l, i int, err error) {
	if d.Ver == 0 {
		return d.Tag0(b, st)
	}

	if st >= len(b) {
		return 0, 0, st, ErrEndOfBuffer
	}

	i = st

	tag = int(b[i]) & TagMask
	l = int(b[i]) & TagLenMask
	i++

	switch l {
	case Len1:
		if i+1 > len(b) {
			return tag, l, st, ErrEndOfBuffer
		}

		l = Len1 + int(b[i])
		i++
	case Len2:
		if i+2 > len(b) {
			return tag, l, st, ErrEndOfBuffer
		}

		l = Len1 + 0x100
		l += int(b[i]) | int(b[i+1])<<8
		i += 2
	case Len4:
		if i+4 > len(b) {
			return tag, l, st, ErrEndOfBuffer
		}

		l = Len1 + 0x100 + 0x1_0000
		l += int(b[i]) | int(b[i+1])<<8 | int(b[i+2])<<16 | int(b[i+3])<<24
		i += 4
	case Len8:
		return tag, l, st, ErrOverflow
	default:
		// l is embedded
	}

	return tag, l, i, nil
}

func (d Parser) Offset(b []byte, st, l int) (off, i int, err error) {
	if d.Ver == 0 {
		return d.Offset0(b, st, l)
	}

	var long bool
	i = st

	if i == len(b) {
		return 0, st, ErrEndOfBuffer
	}

	if long = b[i] == OffLong; long {
		i++
	}

	off, i, err = d.BasicOffset(b, i)
	if err != nil {
		return off, i, err
	}

	if !long {
		off += l
	}

	return off, i, nil
}

func (d Parser) BasicOffset(b []byte, st int) (off, i int, err error) {
	i = st

	if i == len(b) {
		return 0, st, ErrEndOfBuffer
	}

	off = int(b[i])
	i++

	switch off {
	case Off1:
		if i+1 > len(b) {
			return off, st, ErrEndOfBuffer
		}

		off = Off1 + int(b[i])
		i++
	case Off2:
		if i+2 > len(b) {
			return off, st, ErrEndOfBuffer
		}

		off = Off1 + 0x100
		off += int(b[i]) | int(b[i+1])<<8
		i += 2
	case Off4:
		if i+4 > len(b) {
			return off, st, ErrEndOfBuffer
		}

		off = Off1 + 0x100 + 0x1_0000
		off += int(b[i]) | int(b[i+1])<<8 | int(b[i+2])<<16 | int(b[i+3])<<24
		i += 4
	case Off8:
		return off, st, ErrOverflow
	default:
		// off is embedded
	}

	return off, i, nil
}

func (d Parser) Meta(b []byte, st int) (meta, l, i int, err error) {
	i = st
	if i == len(b) {
		return 0, 0, st, ErrEndOfBuffer
	}

	meta = int(b[i])
	i++

	meta, l = meta&MetaTagMask, meta&MetaLenMask

	if l < MetaLenWide {
		l = 1 << l

		return
	}

	if i == len(b) {
		return 0, 0, st, ErrEndOfBuffer
	}

	l = int(b[i])
	i++

	if l < Off1 {
		return
	}

	return 0, 0, st, ErrOverflow
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

func (w *Dumper) ReadFrom(r io.Reader) (tot int64, err error) {
	var keep, n, m int

	p := make([]byte, 0x10000)

	for {
		n, err = r.Read(p[keep:])
		if n == 0 {
			break
		}

		tot += int64(n)

		n += keep

		m, err = w.Write(p[:n])
		keep = copy(p, p[m:n])

		if err != nil && err != ErrEndOfBuffer { //nolint:errorlint
			break
		}
	}

	if errors.Is(err, io.EOF) {
		err = nil
	}

	if keep != 0 && err == nil {
		err = io.ErrUnexpectedEOF
	}

	return tot, err
}

// Write implements io.Writer.
func (w *Dumper) Write(p []byte) (i int, err error) { //nolint:gocognit
	w.b = w.b[:0]

	defer func() {
		w.d.boff += int64(i)

		if w.GlobalOffset >= 0 {
			w.GlobalOffset += int64(i)
		}

		if w.Writer == nil {
			return
		}

		_, e := w.Writer.Write(w.b)
		if err == nil {
			err = e
		}
	}()

	var tag, l, meta int

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

			if w.Debug != nil && i != st {
				w.Debug(w.d.boff+int64(st), w.d.pos, 'p', i-st, 0)
			}

			continue
		}

		tag, l, i, err = w.d.Tag(p, i)
		if err != nil {
			return st, err
		}

		//	println("loop", i, tag>>7, l)

		switch {
		case tag == Meta && l == 0:
			meta, l, i, err = w.d.Meta(p, i)
			if err != nil {
				return
			}

			if i+l > len(p) {
				return i, ErrEndOfBuffer
			}

			if meta == MetaVer && l == 1 {
				w.d.Ver = int(p[i])
			}

			w.b = hfmt.Appendf(w.b, "meta %2x %x  %q\n", meta>>3, l, p[i:i+l])

			if w.Debug != nil {
				w.Debug(w.d.boff+int64(st), w.d.pos, 'm', l, meta)
			}

			i += l
		case tag == Literal:
			if i+l > len(p) {
				return i, ErrEndOfBuffer
			}

			w.b = hfmt.Appendf(w.b, "lit  %4x        %q\n", l, p[i:i+l])

			if w.Debug != nil {
				w.Debug(w.d.boff+int64(st), w.d.pos, 'l', l, 0)
			}

			i += l
			w.d.pos += int64(l)
		case tag == Copy:
			var off int

			off, i, err = w.d.Offset(p, i, l)
			if err != nil {
				return st, err
			}

			w.b = hfmt.Appendf(w.b, "copy %4x  off %4x  %x\n", l, off, p[st:i])

			if w.Debug != nil {
				w.Debug(w.d.boff+int64(st), w.d.pos, 'c', l, off)
			}

			w.d.pos += int64(l)
		}
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
