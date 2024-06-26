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
	// Decoder is a low level decoder.
	// Use Reader to just get data decompressed.
	//
	// It's here to be able to reuse polished approaches.
	Decoder struct {
		Ver int
	}

	// Reader is eazy decompressor.
	Reader struct {
		io.Reader

		d Decoder

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

		r Reader

		Debug        func(ioff, ooff int64, tag byte, l, off int)
		GlobalOffset int64

		b low.Buf
	}
)

var (
	ErrEndOfBuffer        = stderrors.New("unexpected end of buffer")
	ErrEndOfStream        = stderrors.New("end of stream")
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
func (r *Reader) Reset(rd io.Reader) {
	r.ResetBytes(r.b[:0])
	r.Reader = rd
}

// ResetBytes resets the stream and replaces b.
func (r *Reader) ResetBytes(b []byte) {
	r.Reader = nil
	r.b = b

	r.block = r.block[:0]
	r.pos = 0

	r.i = 0
	r.boff = 0

	r.state = 0
}

// Read is io.Reader implementation.
func (r *Reader) Read(p []byte) (n int, err error) {
	var m, i int

	for n < len(p) && err == nil {
		m, i, err = r.read(p[n:], r.i)

		n += m
		r.i = i

		if n == len(p) {
			//	err = nil
			break
		}

		if err != ErrEndOfBuffer { //nolint:errorlint
			continue
		}

		err = r.more()
		if errors.Is(err, io.EOF) && (r.state != 0 || r.i < len(r.b)) {
			err = io.ErrUnexpectedEOF
		}
	}

	return n, err
}

func (r *Reader) read(p []byte, st int) (n, i int, err error) {
	//	defer func() { println("eazy.Decoder.read", st, i, n, err, r.state, r.len, len(r.b), loc.Caller(1).String()) }()
	i = st

	for r.state == 0 {
		i, err = r.readTag(i)
		if err != nil {
			return
		}
	}

	if len(r.block) == 0 {
		return 0, st, errors.New("missed meta")
	}

	if r.state == 'l' && i == len(r.b) {
		return 0, i, ErrEndOfBuffer
	}

	end := r.len
	if end > len(p) {
		end = len(p)
	}

	switch {
	case r.state == 'l':
		end = copy(p[:end], r.b[i:])
		i += end
	case int64(r.off+r.len) <= r.pos:
		end = copy(p[:end], r.block[r.off&r.mask:])
		r.off += end
	case int64(r.off) == r.pos: // zero region
		for j := 0; j < end; {
			j += copy(p[j:end], zeros)
		}
	default:
		rlen := int(r.pos) - r.off
		if rlen == 0 {
			return 0, i, ErrOverflow
		}

		if end > rlen {
			end = rlen
		}

		for j := 0; j < end; {
			j += copy(p[j:end], r.block[(r.off+j)&r.mask:])
		}

		for j := rlen; j < end; {
			j += copy(p[j:end], p[:rlen])
		}

		r.off += end
	}

	r.len -= end

	for n < end {
		m := copy(r.block[int(r.pos)&r.mask:], p[n:end])
		n += m
		r.pos += int64(m)
	}

	if r.len == 0 {
		r.state = 0
	}

	return
}

func (r *Reader) readTag(st int) (i int, err error) {
	st, err = r.checkLegacy(st)
	if err != nil {
		return st, err
	}

	i = st

	// skip zero padding
	for i < len(r.b) && r.b[i] == 0 {
		i++
	}

	st = i

	tag, l, i, err := r.d.Tag(r.b, st)
	if err != nil {
		return st, err
	}

	if r.boff == 0 && st == 0 && r.b[st] != Meta && r.RequireMagic {
		return st, ErrNoMagic
	}

	//	println("readTag", tag, l, st, i, r.i, len(r.b))

	if tag == Meta && l == 0 {
		return r.continueMetaTag(i)
	}

	if r.BlockSizeLimit != 0 && l > r.BlockSizeLimit {
		return st, ErrOverflow
	}

	switch tag {
	case Literal:
		r.state = 'l'
		r.off = 0
	case Copy:
		r.off, i, err = r.d.Offset(r.b, i, l)
		if err != nil {
			return st, err
		}
		if r.off > len(r.block) {
			return st, ErrOverflow
		}

		r.off = int(r.pos) - r.off

		r.state = 'c'
	default:
		return st, errors.New("unsupported tag: %x", tag)
	}

	r.len = l

	return i, nil
}

func (r *Reader) continueMetaTag(st int) (i int, err error) {
	i = st
	st--

	meta, l, i, err := r.d.Meta(r.b, i)
	if err != nil {
		return
	}

	if r.boff == 0 && st == 0 && meta != MetaMagic && r.RequireMagic {
		return st, ErrNoMagic
	}

	if i+l > len(r.b) {
		return st, ErrEndOfBuffer
	}

	reqLen := [...]int{4, 1, 1, 1}

	if j := meta >> 3; j < len(reqLen) && l != reqLen[j] {
		return st, ErrUnsupportedMeta
	}

	switch meta {
	case MetaMagic:
		if !bytes.Equal(r.b[i:i+l], []byte("eazy")) {
			return st, ErrBadMagic
		}
	case MetaVer:
		r.d.Ver = int(r.b[i])
		if r.d.Ver > maxVer {
			return st, fmt.Errorf("%w: %v", ErrUnsupportedVersion, r.d.Ver)
		}
	case MetaReset:
		bs := int(r.b[i])
		if bs > 32 || l != 1 || r.BlockSizeLimit != 0 && 1<<bs > r.BlockSizeLimit {
			return st, ErrOverflow
		}

		r.reset(bs)
	case MetaEndOfStream:
		return i + l, ErrEndOfStream
	default:
		if r.SkipUnsupportedMeta {
			break
		}

		return st, fmt.Errorf("%w: 0x%x", ErrUnsupportedMeta, meta)
	}

	i += l

	return i, nil
}

func (r *Reader) checkLegacy(st int) (int, error) {
	check := func(legacy string, st int) (int, error) {
		db := r.b[st:]

		if len(db) < len(legacy)+1 && bytes.Equal(db, []byte(legacy)[:len(db)]) { //nolint:gocritic
			return st, ErrEndOfBuffer
		}

		if len(db) >= len(legacy)+1 && bytes.Equal(db[:len(legacy)], []byte(legacy)) { //nolint:gocritic
			i := len(legacy)

			bs := int(db[i])
			i++

			r.reset(bs)

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

func (r *Reader) reset(bs int) {
	bs = 1 << bs

	if bs <= cap(r.block) {
		r.block = r.block[:bs]

		for i := 0; i < bs; {
			i += copy(r.block[i:], zeros)
		}
	} else {
		r.block = make([]byte, bs)
	}

	r.pos = 0
	r.mask = bs - 1

	r.state = 0
}

func (d Decoder) tag0(b []byte, st int) (tag, l, i int, err error) {
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

func (d Decoder) offset0(b []byte, st, l int) (off, i int, err error) {
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

func (d Decoder) Tag(b []byte, st int) (tag, l, i int, err error) {
	if d.Ver == 0 {
		return d.tag0(b, st)
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

func (d Decoder) Offset(b []byte, st, l int) (off, i int, err error) {
	if d.Ver == 0 {
		return d.offset0(b, st, l)
	}

	var long bool
	i = st

	if i == len(b) {
		return 0, st, ErrEndOfBuffer
	}

	if long = b[i] == OffLong; long {
		i++
	}

	off, i, err = d.basicOffset(b, i)
	if err != nil {
		return off, i, err
	}

	if !long {
		off += l
	}

	return off, i, nil
}

func (d Decoder) basicOffset(b []byte, st int) (off, i int, err error) {
	i = st

	if i == len(b) {
		return 0, st, ErrEndOfBuffer
	}

	off = int(b[i])
	i++

	// this is slower than 3 ifs in each switch case
	//	if off >= Off1 && i+1<<(off-Off1) > len(b) {
	//		return off, st, ErrEndOfBuffer
	//	}

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

func (d Decoder) Meta(b []byte, st int) (meta, l, i int, err error) {
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

func (r *Reader) more() (err error) {
	if r.Reader == nil {
		return io.EOF
	}

	copy(r.b, r.b[r.i:])
	r.b = r.b[:len(r.b)-r.i]
	r.boff += int64(r.i)
	r.i = 0

	end := len(r.b)

	if len(r.b) == 0 {
		r.b = make([]byte, 1024)
	} else {
		r.b = append(r.b, 0, 0, 0, 0, 0, 0, 0, 0)
	}

	r.b = r.b[:cap(r.b)]

	n, err := r.Reader.Read(r.b[end:])
	//	println("more", r.i, end, end+n, n, len(r.b))
	r.b = r.b[:end+n]

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
		w.r.boff += int64(i)

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

		w.b = hfmt.Appendf(w.b, "%4x  %6x  ", i, w.r.pos)

		st := i

		for i < len(p) && p[i] == 0 {
			i++
		}

		if i != st {
			w.b = hfmt.Appendf(w.b, "pad  %4x\n", i-st)

			if w.Debug != nil && i != st {
				w.Debug(w.r.boff+int64(st), w.r.pos, 'p', i-st, 0)
			}

			continue
		}

		tag, l, i, err = w.r.d.Tag(p, i)
		if err != nil {
			return st, err
		}

		//	println("loop", i, tag>>7, l)

		switch {
		case tag == Meta && l == 0:
			meta, l, i, err = w.r.d.Meta(p, i)
			if err != nil {
				return
			}

			if i+l > len(p) {
				return i, ErrEndOfBuffer
			}

			if meta == MetaVer && l == 1 {
				w.r.d.Ver = int(p[i])
			}

			w.b = hfmt.Appendf(w.b, "meta %2x %x  %q\n", meta>>3, l, p[i:i+l])

			if w.Debug != nil {
				w.Debug(w.r.boff+int64(st), w.r.pos, 'm', l, meta)
			}

			i += l
		case tag == Literal:
			if i+l > len(p) {
				return i, ErrEndOfBuffer
			}

			w.b = hfmt.Appendf(w.b, "lit  %4x        %q\n", l, p[i:i+l])

			if w.Debug != nil {
				w.Debug(w.r.boff+int64(st), w.r.pos, 'l', l, 0)
			}

			i += l
			w.r.pos += int64(l)
		case tag == Copy:
			var off int
			long := ""

			if i < len(p) && p[i] == OffLong {
				long = "  (long)"
			}

			off, i, err = w.r.d.Offset(p, i, l)
			if err != nil {
				return st, err
			}

			w.b = hfmt.Appendf(w.b, "copy %4x  off %4x%s\n", l, off, long)

			if w.Debug != nil {
				w.Debug(w.r.boff+int64(st), w.r.pos, 'c', l, off)
			}

			w.r.pos += int64(l)
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

	w.b = hfmt.Appendf(w.b, "%6x  ", w.r.pos)

	return nil
}
