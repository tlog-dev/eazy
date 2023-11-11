package eazy

import (
	"fmt"
	"io"
	"os"
	"unsafe"
)

type (
	// Writer is eazy compressor.
	Writer struct {
		io.Writer

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
	Len8
	Len4
	Len2
	Len1
)

// Offset lengths.
const (
	_ = 1<<8 - iota
	Off8
	Off4
	Off2
	Off1
)

// Meta tags.
const (
	// len: 1 2 4 8  16 32 64 Len1

	MetaMagic = iota << 3 // 4: "eazy"
	MetaReset             // 1: block_size_log

	MetaTagMask = 0b1111_1000 // tag | log(size)
)

// FileMagic is the first bytes in a compressed stream.
const FileMagic = "\x80\x02eazy"

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

func (w *Writer) reset() {
	w.pos = 0

	for i := 0; i < len(w.block); {
		i += copy(w.block[i:], zeros)
	}
	for i := range w.ht {
		w.ht[i] = 0
	}
}

// ResetSize recreates Writer trying reuse allocated objects.
func (w *Writer) ResetSize(wr io.Writer, block, htable int) {
	w.Writer = wr
	w.pos = 0
	w.init(block, htable)
}

func (w *Writer) init(bs, hs int) {
	if (bs-1)&bs != 0 || bs < 32 || bs > 1<<31 {
		panic("block size must be a power of two")
	}

	if (hs-1)&hs != 0 || hs < 4 {
		panic("hash table size must be a power of two")
	}

	w.mask = bs - 1

	if bs <= cap(w.block) {
		w.block = w.block[:bs]

		for i := 0; i < len(w.block); {
			i += copy(w.block[i:], zeros)
		}
	} else {
		w.block = make([]byte, bs)
	}

	w.hsh = uint(2)
	for 1<<(32-w.hsh) != hs {
		w.hsh++
	}

	if hs <= cap(w.ht) {
		w.ht = w.ht[:hs]

		for i := range w.ht {
			w.ht[i] = 0
		}
	} else {
		w.ht = make([]uint32, hs)
	}
}

// Write is io.Writer implementation.
func (w *Writer) Write(p []byte) (done int, err error) { //nolint:gocognit
	w.b = w.b[:0]

	if w.pos == 0 {
		w.b = w.appendHeader(w.b)
	}

	start := int(w.pos)

	for i := 0; i+4 < len(p); {
		h := *(*uint32)(unsafe.Pointer(&p[i])) * 0x1e35a7bd >> w.hsh

		pos := int(w.ht[h])
		w.ht[h] = uint32(start + i)

		if off := int(w.pos) - pos; off <= i-done+4 || off >= len(w.block) {
			i++
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

		for iend < len(p) && p[iend] == w.block[end&w.mask] {
			iend++
			end++
		}

		if end-st <= 4 {
			i++
			continue
		}

		off := start + i - pos
		lit := ist - done
		cst := st + off
		cend := end + off

		if x := cend - len(w.block) - st; x > 0 {
			//	dpr("block long  intersection: reduce end by %4x\n", x)
			end -= x
			iend -= x
		}

		if x := end - cst + lit; x > 0 {
			//	dpr("literal     intersection: reduce end by %4x\n", x)
			end -= x
			iend -= x

			/*
				j := done
				for iend < len(p) && j < ist && p[iend] == p[j] && end < cst && cend < st+len(w.block) {
					iend++
					cend++
					end++
					j++
				}

				dpr("literal     intersection: added back %4x\n", j-done)
			*/
		}

		if end-st <= 4 {
			i++
			continue
		}

		cend = end + off

		/*
			dpr(""+
				"lit %4x %4x (%4x)  pos %6x %6x  blk %4x %4x  %q\n"+
				"cpy %4x %4x (%4x)  pos %6x %6x  blk %4x %4x  %q\n"+
				"i   %4x pos %6x   bck %6x %6x  blk %4x %4x  off %4x  st %4x end %4x\n",
				done, ist, lit, cst-lit, cst, (cst-lit)&w.mask, cst&w.mask, p[done:ist],
				ist, iend, iend-ist, cst, cend, cst&w.mask, cend&w.mask, p[ist:iend],
				i, pos, st, end, st&w.mask, end&w.mask, off, st-pos, end-pos,
			)
		*/

		if !(st&w.mask >= cend&w.mask || cst&w.mask >= end&w.mask) {
			panic(pos)
		}

		if done < ist {
			w.appendLiteral(p, done, ist)
			w.copyData(p, done, ist)
		}

		w.appendCopy(st, end)
		w.copyData(p, ist, iend)

		h = *(*uint32)(unsafe.Pointer(&p[i+1])) * 0x1e35a7bd >> w.hsh
		w.ht[h] = uint32(start + i + 1)

		i = iend
		done = iend
	}

	if done < len(p) {
		w.appendLiteral(p, done, len(p))
		w.copyData(p, done, len(p))

		done = len(p)
	}

	n, err := w.Writer.Write(w.b)
	w.written += int64(n)

	if err != nil || n != len(w.b) {
		w.reset()
	}

	return done, err
}

func (w *Writer) appendHeader(b []byte) []byte {
	if w.AppendMagic {
		b = w.appendMagic(b)
	}

	b = w.appendReset(b, len(w.block))

	return b
}

func (w *Writer) appendReset(b []byte, block int) []byte {
	bs := 0
	for q := block; q != 1; q >>= 1 {
		bs++
	}

	return append(b, Meta, MetaReset|0, byte(bs)) //nolint:staticcheck
}

func (w *Writer) appendMagic(b []byte) []byte {
	return append(b, Meta, MetaMagic|2, 'e', 'a', 'z', 'y')
}

func (w *Writer) appendLiteral(d []byte, st, end int) {
	w.b = w.appendTag(w.b, Literal, end-st)
	w.b = append(w.b, d[st:end]...)
}

func (w *Writer) appendCopy(st, end int) {
	w.b = w.appendTag(w.b, Copy, end-st)
	w.b = w.appendOff(w.b, int(w.pos)-end)
}

func (w *Writer) copyData(d []byte, st, end int) {
	for st < end {
		n := copy(w.block[int(w.pos)&w.mask:], d[st:end])
		st += n
		w.pos += int64(n)
	}
}

func (w *Writer) appendTag(b []byte, tag byte, l int) []byte {
	switch {
	case l < Len1:
		return append(b, tag|byte(l))
	case l <= 0xff:
		return append(b, tag|Len1, byte(l))
	case l <= 0xffff:
		return append(b, tag|Len2, byte(l>>8), byte(l))
	case l <= 0xffff_ffff:
		return append(b, tag|Len4, byte(l>>24), byte(l>>16), byte(l>>8), byte(l))
	default:
		return append(b, tag|Len8, byte(l>>56), byte(l>>48), byte(l>>40), byte(l>>32), byte(l>>24), byte(l>>16), byte(l>>8), byte(l))
	}
}

func (w *Writer) appendOff(b []byte, l int) []byte {
	switch {
	case l < Off1:
		return append(b, byte(l))
	case l <= 0xff:
		return append(b, Off1, byte(l))
	case l <= 0xffff:
		return append(b, Off2, byte(l>>8), byte(l))
	case l <= 0xffff_ffff:
		return append(b, Off4, byte(l>>24), byte(l>>16), byte(l>>8), byte(l))
	default:
		return append(b, Off8, byte(l>>56), byte(l>>48), byte(l>>40), byte(l>>32), byte(l>>24), byte(l>>16), byte(l>>8), byte(l))
	}
}

//nolint:unused,deadcode,goprintffuncname
func dpr(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, format, args...)
}
