package eazy

import (
	"fmt"
	"io"
	"math/bits"
	"unsafe"
)

type (
	// Encoder is a low level encoder.
	// Use Writer to just get data compressed.
	Encoder struct {
		Ver int
	}

	// Writer is eazy compressor.
	Writer struct {
		io.Writer

		e Encoder

		AppendMagic bool // Append FileMagic in the beginning of the stream. true by default.

		// output
		b       []byte
		written int64

		block []byte
		mask  int
		pos   int64

		ht  []uint32
		hsh uint
	}
)

// Byte multipliers.
const (
	B = 1 << (iota * 10)
	KiB
	MiB
	GiB
)

// Tags.
const (
	Literal = iota << 7
	Copy

	TagMask    = 0b1000_0000
	TagLenMask = 0b0111_1111

	// Padding can be safely added between any writes
	// and will be skipped by Reader.
	Padding = 0x00

	// Meta is Copy tag with zero length.
	Meta = Copy | 0 //nolint:staticcheck
)

// Tag lengths.
const (
	_ = 1<<7 - iota
	LenAlt
	Len4
	Len2
	Len1
)

// Offset lengths.
const (
	_ = 1<<8 - iota
	OffAlt
	Off4
	Off2
	Off1

	OffLong = OffAlt
)

// Meta tags.
const (
	// len: 1 2 4 8  16 32 LenWide Len0

	MetaMagic = iota << 3 // 4: "eazy"
	MetaVer               // 1: ver
	MetaReset             // 1: block_size_log
	MetaBreak             // 0

	//nolint:godot
	// MetaCRC32IEEE
	// MetaXXHash32

	MetaTagMask = 0b1111_1000 // tag | log(size)
	MetaLenMask = 0b0000_0111
	MetaLenWide = MetaLenMask - 1
	MetaLen0    = MetaLenMask - 0
)

const (
	// Magic is the first bytes in a compressed stream.
	Magic = "\x80\x02eazy"

	// Version is the latest supported format version.
	Version = 0

	minCopyChunk = 6
)

var zeros = make([]byte, 1024)

// NewWriter creates new compressor writing to wr, with block size,
// and hash table size.
//
// Block size is haw far back similar byte sequences are searched.
// Hash table size is how many sequences we remember.
// Both values should be chosen for specific use case, but
// 1 * eazy.MiB block and 1024 table size is a good starting point.
//
// Both block and table sizes must be a power of two.
func NewWriter(wr io.Writer, block, htable int) *Writer {
	w := &Writer{
		Writer:      wr,
		AppendMagic: true,
		e: Encoder{
			Ver: Version,
		},
	}

	w.init(block, htable)

	return w
}

// Reset resets stream. This is equivalent to creating a new Writer
// with the same block and hash table size.
func (w *Writer) Reset(wr io.Writer) {
	w.Writer = wr
	w.reset()
}

// ResetSize recreates Writer trying reuse allocated objects.
func (w *Writer) ResetSize(wr io.Writer, block, htable int) {
	w.Writer = wr
	w.init(block, htable)
	w.reset()
}

func (w *Writer) init(bs, hs int) {
	if (bs-1)&bs != 0 || bs < 32 || bs > 1<<31 {
		panic("block size must be a power of two (32 < bs < 1<<31)")
	}

	if (hs-1)&hs != 0 || hs < 4 {
		panic("hash table size must be a power of two (hs > 4)")
	}

	w.mask = bs - 1

	if bs <= cap(w.block) {
		w.block = w.block[:bs]
	} else {
		w.block = make([]byte, bs)
	}

	w.hsh = 32 - uint(bits.Len(uint(hs)-1))

	if hs <= cap(w.ht) {
		w.ht = w.ht[:hs]
	} else {
		w.ht = make([]uint32, hs)
	}
}

func (w *Writer) reset() {
	w.pos = 0
	w.written = 0

	for i := 0; i < len(w.block); {
		i += copy(w.block[i:], zeros)
	}

	for i := range w.ht {
		w.ht[i] = 0
	}
}

// Write is io.Writer implementation.
//
// One Write results in one Write with comressed data to the underlaying io.Writer.
// Header meta is added to the first Write.
func (w *Writer) Write(p []byte) (done int, err error) {
	w.b = w.b[:0]

	if w.written == 0 {
		w.b = w.appendHeader(w.b)
	}

	start := int(w.pos)

	for i := 0; i+4 <= len(p); {
		h := w.hash(p, i)

		pos := int(w.ht[h])
		w.ht[h] = uint32(start + i)

		off := pos - int(w.pos) // forward offset

		if -off > len(w.block) {
			i++
			continue
		}

		// runlen encoding
		if off >= 0 && i > done+off {
			done, i = w.writeRunlen(p, done, done+off, i)

			continue
		}

		// extend backward

		ist := i - 1
		st := pos - 1

		for ist >= done && p[ist] == w.block[st&w.mask] {
			ist--
			st--
		}

		ist++
		st++

		// extend forward

		iend := i
		end := pos

		for iend+8 < len(p) && end&w.mask+8 < len(w.block) && equal8(p[iend:], w.block[end&w.mask:]) {
			iend += 8
			end += 8
		}

		for iend < len(p) && p[iend] == w.block[end&w.mask] {
			iend++
			end++
		}

		// check overflows

		// Window               p arg
		//
		// xxxyyy___ccc____     xxxyyy // xxx - literal, yyy duplicate
		// ^  ^  ^  ^  ^        ^
		// |  |  |  |  ' - end  ' - w.pos
		// |  |  |  ' - st
		// |  |  ' - bend
		// |  ' - bst
		// ' - blit
		//
		// Cases:
		// _________ccc____ // no intersections mod len(w.block)
		// _____ccc________ // ccc intersects yyy
		// c_____________cc // ccc intersects xxx
		// _______________c // yyy is repetition of c
		//

		blit := int(w.pos) - len(w.block)
		//	bst := blit + (ist - done)
		bend := blit + (iend - done)

		//	dpr("cmp %4x %4x  %2x  pos %4x %x  hash %x\n", st, end, i, pos, w.pos, h)

		if diff := bend - st; diff > 0 {
			//	dpr("first\n")
			end -= diff
			iend -= diff
		}

		if diff := (end - len(w.block)) - blit; diff > 0 {
			//	dpr("second\n")
			end -= diff
			iend -= diff
		}

		if end-st < minCopyChunk {
			i++
			continue
		}

		if done < ist {
			w.appendLiteral(p, done, ist)
			w.copyData(p, done, ist)
		}

		if int(w.pos)-st > len(w.block) {
			panic("too big offset")
		}

		w.appendCopy(st, end)
		w.copyData(p, ist, iend)

		if i+1+4 <= len(p) {
			h = w.hash(p, i+1)
			w.ht[h] = uint32(start + i + 1)
		}

		i = iend
		done = iend
	}

	if done < len(p) {
		w.appendLiteral(p, done, len(p))
		w.copyData(p, done, len(p))

		done = len(p)
	}

	err = w.write()
	if err != nil {
		return 0, err
	}

	return done, nil
}

// WriteHeader manually triggers write of required header meta tags.
// It's not required to call this method manually,
// header is written automatically with the first w.Write.
func (w *Writer) WriteHeader() error {
	if w.written != 0 {
		return nil
	}

	w.b = w.appendHeader(w.b[:0])

	return w.write()
}

// WriteBreak writes Break marker which can be used to separate chunks of data in the same compression stream.
// Reader returns ErrBreak when it encounters the marker and the Reader state stays valid.
//
// Marker takes 2 bytes in comressed stream.
//
// See ErrBreak for more information.
func (w *Writer) WriteBreak() error {
	w.b = w.b[:0]

	if w.written == 0 {
		w.b = w.appendHeader(w.b)
	}

	w.b = append(w.b, Meta, MetaBreak|MetaLen0)

	return w.write()
}

func (w *Writer) write() (err error) {
	n, err := w.Writer.Write(w.b)
	w.written += int64(n)

	if err != nil || n != len(w.b) {
		w.reset()
	}

	return err
}

func (w *Writer) writeZeros(p []byte, done, i int) (nextdone, iend int) {
	iend = i

	for iend+8 < len(p) && equal8(p[iend:], zeros) {
		iend += 8
	}

	for iend < len(p) && p[iend] == 0 {
		iend++
	}

	for i > done && p[i-1] == 0 {
		i--
	}

	if iend-i < minCopyChunk {
		return done, i + 1
	}

	//	dpr("zeros %4x %4x %4x\n", done, i, iend)

	if done != i {
		w.appendLiteral(p, done, i)
		w.copyData(p, done, i)
	}

	w.b = w.e.Tag(w.b, Copy, iend-i)
	w.b = append(w.b, OffLong, 0)

	w.copyData(p, i, iend)

	return iend, iend
}

func (w *Writer) writeRunlen(p []byte, done, st, i int) (nextdone, iend int) {
	if st+8 < len(p) && equal8(p[st:], zeros) {
		return w.writeZeros(p, done, st)
	}

	jf := 0

	for i+jf < len(p) && p[st+jf] == p[i+jf] {
		jf++
	}

	jb := -1

	for st+jb >= 0 && i+jb >= done && p[st+jb] == p[i+jb] {
		jb--
	}

	jb++

	if jf-jb < minCopyChunk {
		return done, i + 1
	}

	if i-st >= len(w.block)-8 {
		//	dpr("cut %4x %4x %4x %4x %4x\n", done, st, i, jb, jf)

		iend := done + i - st

		w.appendLiteral(p, done, iend)
		w.copyData(p, done, iend)

		return iend, iend
	}

	//	dpr("runlen %4x %4x %4x %4x %4x\n", done, st, i, jb, jf)

	ist := i + jb
	iend = i + jf

	w.appendLiteral(p, done, ist)
	w.copyData(p, done, ist)

	w.b = w.e.Tag(w.b, Copy, iend-ist)
	w.b = w.e.Offset(w.b, i-st, iend-ist)

	w.copyData(p, ist, iend)

	return iend, iend
}

func (w *Writer) hash(p []byte, i int) uint32 {
	return *(*uint32)(unsafe.Pointer(&p[i])) * 0x1e35a7bd >> w.hsh
}

func (w *Writer) appendHeader(b []byte) []byte {
	if w.AppendMagic {
		b = w.appendMagic(b)
	}

	if w.e.Ver != 0 {
		b = append(b, Meta, MetaVer|0, byte(w.e.Ver)) //nolint:staticcheck
	}

	b = w.appendReset(b, len(w.block))

	return b
}

func (w *Writer) appendMagic(b []byte) []byte {
	return append(b, Meta, MetaMagic|2, 'e', 'a', 'z', 'y')
}

func (w *Writer) appendReset(b []byte, block int) []byte {
	bs := bits.TrailingZeros(uint(block))

	return append(b, Meta, MetaReset|0, byte(bs)) //nolint:staticcheck
}

func (w *Writer) appendLiteral(d []byte, st, end int) {
	w.b = w.e.Tag(w.b, Literal, end-st)
	w.b = append(w.b, d[st:end]...)
}

func (w *Writer) appendCopy(st, end int) {
	w.b = w.e.Tag(w.b, Copy, end-st)
	w.b = w.e.Offset(w.b, int(w.pos)-st, end-st)
}

func (w *Writer) copyData(d []byte, st, end int) {
	for st < end {
		n := copy(w.block[int(w.pos)&w.mask:], d[st:end])
		st += n
		w.pos += int64(n)
	}
}

func (e Encoder) Tag(b []byte, tag byte, l int) []byte {
	const reserve = 8

	if l < Len1 {
		return append(b, tag|byte(l))
	}

	l -= Len1

	if l < 0x100 {
		return append(b, tag|Len1, byte(l))
	}

	l -= 0x100

	if l < 0x1_0000 {
		return append(b, tag|Len2, byte(l), byte(l>>8))
	}

	l -= 0x1_0000

	if l < 0x1_0000_0000-reserve {
		return append(b, tag|Len4, byte(l), byte(l>>8), byte(l>>16), byte(l>>24))
	}

	panic("too big length")
}

func (e Encoder) Offset(b []byte, off, l int) []byte {
	const reserve = 8

	if off >= l {
		off -= l
	} else {
		b = append(b, OffLong)
	}

	if off < Off1 {
		return append(b, byte(off))
	}

	off -= Off1

	if off < 0x100 {
		return append(b, Off1, byte(off))
	}

	off -= 0x100

	if off < 0x1_0000 {
		return append(b, Off2, byte(off), byte(off>>8))
	}

	off -= 0x1_0000

	if off < 0x1_0000_0000-reserve {
		return append(b, Off4, byte(off), byte(off>>8), byte(off>>16), byte(off>>24))
	}

	panic("too big offset")
}

func (e Encoder) Meta(b []byte, meta, l int) []byte {
	if meta&^MetaTagMask != 0 {
		panic(meta)
	}

	if l == 0 {
		return append(b, Meta, byte(meta)|MetaLen0)
	}

	if l < MetaLenWide && l&(l-1) == 0 {
		l = bits.Len(uint(l)) - 1
		return append(b, Meta, byte(meta)|byte(l))
	}

	if l < Off1 {
		return append(b, Meta, byte(meta)|MetaLenWide, byte(l))
	}

	b = append(b, Meta, byte(meta)|MetaLenWide)
	b = e.Offset(b, l, 0)

	return b
}

//nolint:unused,deadcode,goprintffuncname
func dpr(format string, args ...interface{}) {
	println(fmt.Sprintf(format, args...))
}

func equal8(x, y []byte) bool {
	return *(*uint64)(unsafe.Pointer(&x[0])) ==
		*(*uint64)(unsafe.Pointer(&y[0]))
}
