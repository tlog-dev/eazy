package eazy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

type (
	// Decoder is a low level decoder.
	// Use Reader to just get data decompressed.
	Decoder struct {
		Ver int
	}

	// Reader is eazy decompressor.
	Reader struct {
		io.Reader

		d Decoder

		block []byte
		mask  int
		pos   int64 // output stream position

		BlockSizeLimit      int
		RequireMagic        bool
		SkipUnsupportedMeta bool

		// current tag
		state    byte
		off, len int // off is absolute value

		// input
		b    []byte
		i    int
		boff int64 // buffer b offset in the input stream
	}

	// Dumper is a debug printer for compressed data.
	Dumper struct {
		io.Writer

		r Reader

		Debug func(ioff, iend, ooff int64, tag byte, l, off int)

		GlobalOffset int64

		b []byte
		p []byte // for ReadFrom
	}
)

var (
	ErrBadMagic           = errors.New("bad magic")
	ErrBlockSizeOverLimit = errors.New("block size is more than the limit")
	ErrNoMagic            = errors.New("no magic")
	ErrOverflow           = errors.New("length/offset overflow")
	ErrShortBuffer        = io.ErrShortBuffer
	ErrUnsupportedMeta    = errors.New("unsupported meta tag")
	ErrUnsupportedVersion = errors.New("unsupported file format version")

	// ErrBreak is returned when a user set Break marker is reached.
	// It allows to separate chunks of data while compressing them in the same "block".
	//
	// One possible use case is separating protobuf messages with the marker
	// instead of varlen encoded length added before the message.
	// That way you can start compressing a big message not knowing its length in advance.
	//
	// It's written with Writer.WriteBreak method.
	// Readers stays valid after returning this error.
	ErrBreak = errors.New("break point")
)

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

		if err != ErrShortBuffer { //nolint:errorlint
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
	//	defer func() { println("eazy.Decoder.read", st, i, n, err, r.state, r.len, len(r.b)) }()
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
		return 0, i, ErrShortBuffer
	}

	end := r.len
	if end > len(p) {
		end = len(p)
	}

	//	dpr("read %q  %x %x %x   %x %x   %x %x", r.state, r.pos, r.off, r.len, st, i, end, len(p))

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
		//           < previous reads, copy from r.block
		//          >  runlen encoded, copy from p
		// abcd______abcd______abcd______
		// ^ r.off   ^ r.pos                // r.block pos
		// ^ 0       ^ run          ^ end   // p pos

		run := int(r.pos) - r.off

		for j := 0; j < run; {
			j += copy(p[j:run], r.block[(r.off+j)&r.mask:])
		}

		for j := run; j < end; {
			j += copy(p[j:end], p[:j])
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
		return st, ErrBlockSizeOverLimit
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
		panic("unreachable")
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
		return st, ErrShortBuffer
	}

	tagLen := [...]int{4, 1, 1, 0}

	if j := meta >> 3; j < len(tagLen) && l != tagLen[j] {
		return st, ErrUnsupportedMeta
	}

	switch meta {
	case MetaMagic:
		if !bytes.Equal(r.b[i:i+l], []byte("eazy")) {
			return st, ErrBadMagic
		}
	case MetaVer:
		r.d.Ver = int(r.b[i])
		if r.d.Ver > Version {
			return st, fmt.Errorf("%w: %v", ErrUnsupportedVersion, r.d.Ver)
		}
	case MetaReset:
		bs := int(r.b[i])
		if bs > 32 || l != 1 || r.BlockSizeLimit != 0 && 1<<bs > r.BlockSizeLimit {
			return st, ErrOverflow
		}

		r.reset(bs)
	case MetaBreak:
		return i + l, ErrBreak
	default:
		if r.SkipUnsupportedMeta {
			break
		}

		return st, fmt.Errorf("%w: 0x%x", ErrUnsupportedMeta, meta)
	}

	i += l

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

func (d Decoder) Tag(b []byte, st int) (tag, l, i int, err error) {
	if st >= len(b) {
		return 0, 0, st, ErrShortBuffer
	}

	i = st

	tag = int(b[i]) & TagMask
	l = int(b[i]) & TagLenMask
	i++

	switch l {
	case Len1:
		if i+1 > len(b) {
			return tag, l, st, ErrShortBuffer
		}

		l = Len1 + int(b[i])
		i++
	case Len2:
		if i+2 > len(b) {
			return tag, l, st, ErrShortBuffer
		}

		l = Len1 + 0x100
		l += int(b[i]) | int(b[i+1])<<8
		i += 2
	case Len4:
		if i+4 > len(b) {
			return tag, l, st, ErrShortBuffer
		}

		l = Len1 + 0x100 + 0x1_0000
		l += int(b[i]) | int(b[i+1])<<8 | int(b[i+2])<<16 | int(b[i+3])<<24
		i += 4
	case LenAlt:
		return tag, l, st, ErrOverflow
	default:
		// l is embedded
	}

	if l < 0 {
		return tag, l, st, ErrOverflow
	}

	return tag, l, i, nil
}

func (d Decoder) Offset(b []byte, st, l int) (off, i int, err error) {
	var long bool
	i = st

	if i == len(b) {
		return 0, st, ErrShortBuffer
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

	if off < 0 {
		return off, st, ErrOverflow
	}

	return off, i, nil
}

func (d Decoder) basicOffset(b []byte, st int) (off, i int, err error) {
	i = st

	if i == len(b) {
		return 0, st, ErrShortBuffer
	}

	off = int(b[i])
	i++

	// this is slower than 3 ifs in each switch case
	//	if off >= Off1 && off <= Off4 && i+1<<(off-Off1) > len(b) {
	//		return off, st, ErrShortBuffer
	//	}

	switch off {
	case Off1:
		if i+1 > len(b) {
			return off, st, ErrShortBuffer
		}

		off = Off1 + int(b[i])
		i++
	case Off2:
		if i+2 > len(b) {
			return off, st, ErrShortBuffer
		}

		off = Off1 + 0x100
		off += int(b[i]) | int(b[i+1])<<8
		i += 2
	case Off4:
		if i+4 > len(b) {
			return off, st, ErrShortBuffer
		}

		off = Off1 + 0x100 + 0x1_0000
		off += int(b[i]) | int(b[i+1])<<8 | int(b[i+2])<<16 | int(b[i+3])<<24
		i += 4
	case OffAlt:
		return off, st, ErrOverflow
	default:
		// off is embedded
	}

	if off < 0 {
		return off, st, ErrOverflow
	}

	return off, i, nil
}

func (d Decoder) Meta(b []byte, st int) (meta, l, i int, err error) {
	i = st
	if i == len(b) {
		return 0, 0, st, ErrShortBuffer
	}

	meta = int(b[i])
	i++

	meta, l = meta&MetaTagMask, meta&MetaLenMask

	if l == MetaLen0 {
		l = 0

		return
	}

	if l < MetaLenWide {
		l = 1 << l

		return
	}

	if i == len(b) {
		return 0, 0, st, ErrShortBuffer
	}

	l = int(b[i])
	i++

	if l < Off1 {
		return
	}

	l, i, err = d.basicOffset(b, i-1)
	if err != nil {
		return
	}

	return
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

	if w.p == nil {
		w.p = make([]byte, 0x10000)
	}

	for {
		n, err = r.Read(w.p[keep:])
		if n == 0 {
			break
		}

		tot += int64(n)

		n = keep + n

		m, err = w.Write(w.p[:n])
		keep = copy(w.p, w.p[m:n])

		if err != nil && err != ErrShortBuffer { //nolint:errorlint
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
			w.b = fmt.Appendf(w.b, "%6x  ", w.GlobalOffset+int64(i))
		}

		w.b = fmt.Appendf(w.b, "%4x  %6x  ", i, w.r.pos)

		st := i

		for i < len(p) && p[i] == 0 {
			i++
		}

		if i != st {
			w.b = fmt.Appendf(w.b, "pad  %4x\n", i-st)

			if w.Debug != nil && i != st {
				w.Debug(w.r.boff+int64(st), w.r.boff+int64(i), w.r.pos, 'p', i-st, 0)
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
				return i, ErrShortBuffer
			}

			if meta == MetaVer && l == 1 {
				w.r.d.Ver = int(p[i])
			}

			w.b = fmt.Appendf(w.b, "meta %2x %x  %q\n", meta>>3, l, p[i:i+l])

			if w.Debug != nil {
				w.Debug(w.r.boff+int64(st), w.r.boff+int64(i), w.r.pos, 'm', l, meta)
			}

			i += l
		case tag == Literal:
			if i+l > len(p) {
				return i, ErrShortBuffer
			}

			w.b = fmt.Appendf(w.b, "lit  %4x        %q\n", l, p[i:i+l])

			if w.Debug != nil {
				w.Debug(w.r.boff+int64(st), w.r.boff+int64(i), w.r.pos, 'l', l, 0)
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

			w.b = fmt.Appendf(w.b, "copy %4x  off %4x%s\n", l, off, long)

			if w.Debug != nil {
				w.Debug(w.r.boff+int64(st), w.r.boff+int64(i), w.r.pos, 'c', l, off)
			}

			w.r.pos += int64(l)
		}
	}

	return i, err
}

func (w *Dumper) Close() error {
	i := 0

	if w.GlobalOffset >= 0 {
		w.b = fmt.Appendf(w.b, "%6x  ", int(w.GlobalOffset)+i)
	}

	w.b = fmt.Appendf(w.b, "%4x  ", i)

	w.b = fmt.Appendf(w.b, "%6x  ", w.r.pos)

	if w.Debug != nil {
		w.Debug(w.r.boff, w.r.boff, w.r.pos, 'e', 0, 0)
	}

	return nil
}

type fmtbuf []byte

func (b fmtbuf) Format(s fmt.State, verb rune) {
	const digits = "0123456789abcdef"

	var t [5]byte
	var ti int

	for i, b := range b {
		ti = 0

		if i != 0 {
			t[ti] = ' '
			ti++
		}

		t[ti] = digits[b>>4]
		ti++
		t[ti] = digits[b&0xf]
		ti++

		_, _ = s.Write(t[:ti])
	}

	copy(t[:], "     ")

	w, ok := s.Width()
	if !ok {
		w = 0
	}

	for i := len(b); i < w; i++ {
		_, _ = s.Write(t[:3])
	}
}
