package eazy

import (
	"bytes"
	"encoding/hex"
	"flag"
	"io"
	"os"
	"testing"

	//"github.com/nikandfor/assert"
	"github.com/nikandfor/errors"
	"github.com/nikandfor/hacked/low"
	"github.com/stretchr/testify/assert"
)

type (
	ByteCounter int64
)

var fileFlag = flag.String("test-file", "log.tlog", "file with tlog logs")

var (
	testData   []byte
	testOff    []int
	testsCount int
)

func TestFileMagic(t *testing.T) {
	var buf low.Buf

	w := NewWriter(&buf, MiB)

	_, err := w.Write([]byte{})
	assert.NoError(t, err)

	if assert.True(t, len(buf) >= len(FileMagic)) {
		assert.Equal(t, FileMagic, string(buf[:len(FileMagic)]))
	}
}

func TestLiteral(t *testing.T) {
	const B = 32

	var buf low.Buf

	w := newWriter(&buf, B, 1)

	n, err := w.Write([]byte("very_first_message"))
	assert.Equal(t, 18, n)
	assert.NoError(t, err)

	t.Logf("buf pos %x ht %x\n%v", w.pos, w.ht, hex.Dump(w.block))
	t.Logf("res\n%v", hex.Dump(buf))
	t.Logf("res\n%v", Dump(buf))

	r := &Reader{
		b: buf,
	}

	p := make([]byte, 100)

	t.Logf("*** read back ***")

	n, err = r.Read(p[:10])
	assert.Equal(t, 10, n)
	assert.NoError(t, err)
	assert.Equal(t, []byte("very_first"), p[:n])

	copy(p[:10], zeros)

	n, err = r.Read(p[:10])
	assert.Equal(t, 8, n)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, []byte("_message"), p[:n])
}

func TestCopy(t *testing.T) {
	const B = 32

	var buf low.Buf

	w := newWriter(&buf, B, 1)

	st := 0

	n, err := w.Write([]byte("prefix_1234_suffix"))
	assert.Equal(t, 18, n)
	assert.NoError(t, err)

	t.Logf("buf pos %x ht %x\n%v", w.pos, w.ht, hex.Dump(w.block))
	t.Logf("res\n%v", hex.Dump(buf[st:]))

	st = len(buf)

	n, err = w.Write([]byte("prefix_567_suffix"))
	assert.Equal(t, 17, n)
	assert.NoError(t, err)

	t.Logf("buf  pos %x ht %x\n%v", w.pos, w.ht, hex.Dump(w.block))
	t.Logf("res\n%v", hex.Dump(buf[st:]))

	r := &Reader{
		b: buf,
	}

	p := make([]byte, 100)

	t.Logf("*** read back ***")

	n, err = r.Read(p[:10])
	assert.Equal(t, 10, n)
	assert.NoError(t, err)
	assert.Equal(t, []byte("prefix_123"), p[:n])

	t.Logf("buf  pos %x\n%v", r.pos, hex.Dump(r.block))

	n, err = r.Read(p[:10])
	assert.Equal(t, 10, n)
	assert.NoError(t, err)
	assert.Equal(t, []byte("4_suffixpr"), p[:n])

	t.Logf("buf  pos %x\n%v", r.pos, hex.Dump(r.block))

	n, err = r.Read(p[:30])
	assert.Equal(t, 15, n)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, []byte("efix_567_suffix"), p[:n])

	t.Logf("buf  pos %x\n%v", r.pos, hex.Dump(r.block))

	//	t.Logf("compression ratio: %.3f", float64(18+17)/float64(len(buf)))
}

func TestBug1(t *testing.T) {
	var b bytes.Buffer

	p := make([]byte, 1000)
	d := NewReader(&b)

	//	tl.Printw("first")

	_, _ = b.Write([]byte{Literal | Meta, MetaReset | 0, 4}) //nolint:staticcheck
	_, _ = b.Write([]byte{Literal | 3, 0x94, 0xa8, 0xfb, Copy | 9})

	n, err := d.Read(p)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.Equal(t, 3, n)

	//	tl.Printw("second")

	_, _ = b.Write([]byte{0xfd, 0x03, 0x65}) // offset

	n, err = d.Read(p)
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, 9, n)
}

func TestOnFile(t *testing.T) {
	err := loadTestFile(t, *fileFlag)
	if err != nil {
		t.Skipf("loading data: %v", err)
	}

	var enc low.BufReader
	var buf []byte

	w := NewWriterHTSize(&enc, 512, 256)
	r := NewReader(&enc)

	for i := 0; i < testsCount; i++ {
		msg := testData[testOff[i]:testOff[i+1]]

		n, err := w.Write(msg)
		assert.NoError(t, err)
		assert.Equal(t, len(msg), n)

		for n > len(buf) {
			buf = append(buf[:cap(buf)], 0, 0, 0, 0, 0, 0, 0, 0)
		}

		n, err = r.Read(buf[:n])
		assert.NoError(t, err)
		assert.Equal(t, len(msg), n)

		assert.Equal(t, msg, []byte(buf[:n]))

		if t.Failed() {
			break
		}
	}

	enc.R = 0
	//r.Reset(&full)
	//	buf = buf[:0]

	var dec low.Buf

	n, err := io.Copy(&dec, r)
	assert.NoError(t, err)
	assert.Equal(t, int(n), dec.Len())

	min := dec.Len()
	assert.Equal(t, testData[:min], dec.Bytes())

	//	t.Logf("metrics: %v  bytes %v  events %v", mm, dec.Len(), testsCount)
	t.Logf("compression ratio %v", dec.LenF()/enc.Buf.LenF())
}

const BlockSize, HTSize = 1024 * 1024, 16 * 1024

func BenchmarkCompressFile(b *testing.B) {
	err := loadTestFile(b, *fileFlag)
	if err != nil {
		b.Skipf("loading data: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	var c ByteCounter
	w := NewWriterHTSize(&c, BlockSize, HTSize)

	//	b.Logf("block %x  ht %x (%x * %x)", len(w.block), len(w.ht)*int(unsafe.Sizeof(w.ht[0])), len(w.ht), unsafe.Sizeof(w.ht[0]))

	written := 0
	for i := 0; i < b.N; i++ {
		j := i % testsCount
		msg := testData[testOff[j]:testOff[j+1]]

		n, err := w.Write(msg)
		if err != nil {
			b.Fatalf("write: %v", err)
		}
		if n != len(msg) {
			b.Fatalf("write %v of %v", n, len(msg))
		}

		written += n
	}

	//	b.Logf("total written: %x  %x", w.pos, w.pos/len(w.block))

	b.ReportMetric(float64(written)/float64(c), "ratio")
	//	b.ReportMetric(float64(c.Operations)/float64(b.N), "writes/op")
	b.SetBytes(int64(written / b.N))
}

func BenchmarkDecompressFile(b *testing.B) {
	err := loadTestFile(b, *fileFlag)
	if err != nil {
		b.Skipf("loading data: %v", err)
	}

	encoded := make(low.Buf, 0, len(testData)/2)
	w := NewWriterHTSize(&encoded, BlockSize, HTSize)

	const limit = 20000

	written := 0
	for i := 0; i < testsCount && i < limit; i++ {
		j := i % testsCount
		msg := testData[testOff[j]:testOff[j+1]]

		n, err := w.Write(msg)
		if err != nil {
			b.Fatalf("write: %v", err)
		}
		if n != len(msg) {
			b.Fatalf("write %v of %v", n, len(msg))
		}

		written += n
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.ReportMetric(float64(written)/float64(len(encoded)), "ratio")

	//	var decoded []byte
	decoded := make(low.Buf, 0, len(testData))
	buf := make([]byte, 4096)
	r := NewReaderBytes(encoded)

	for i := 0; i < b.N/testsCount; i++ {
		r.ResetBytes(encoded)
		decoded = decoded[:0]

		_, err = io.CopyBuffer(&decoded, r, buf)
		assert.NoError(b, err)
	}

	//	b.Logf("decoded %x", len(decoded))

	b.SetBytes(int64(decoded.Len() / testsCount))

	min := len(testData)
	if min > decoded.Len() {
		min = decoded.Len()
	}
	assert.Equal(b, testData[:min], decoded.Bytes())
}

func loadTestFile(tb testing.TB, f string) (err error) {
	tb.Helper()

	if testData != nil {
		return
	}

	testData, err = os.ReadFile(f)
	if err != nil {
		return errors.Wrap(err, "open data file")
	}

	//	var d tlwire.Decoder
	testOff = make([]int, 0, len(testData)/100)

	var st int
	for st < len(testData) {
		testOff = append(testOff, st)

		//	st = d.Skip(testData, st)

		for { // a kinda tlwire.Decoder
			st = nextIndex(st+1, testData,
				[]byte{0xbf, 0x62, '_', 's', 0xcb, 0x50},
				[]byte{0xbf, 0x62, '_', 't', 0xc2, 0x1b})

			//	println(x-st, st, x, len(testData))

			if testData[st-1] != 0xff {
				continue
			}

			break
		}
	}
	testsCount = len(testOff)
	testOff = append(testOff, st)

	tb.Logf("events loaded: %v", testsCount)

	return
}

func FuzzEazy(f *testing.F) {
	f.Add(
		[]byte("prefix_1234_suffix"),
		[]byte("prefix_567_suffix"),
		[]byte("suffix_prefix"),
	)

	f.Add(
		[]byte("aaaaaa"),
		[]byte("aaaaaaaaaaaa"),
		[]byte("aaaaaaaaaaaaaaaaaaaaaaaa"),
	)

	f.Add(
		[]byte("aaaaab"),
		[]byte("aaaaabaaaaaa"),
		[]byte("aaaaaaaaaaabaaaaaaaaaaaa"),
	)

	var wbuf, rbuf bytes.Buffer
	buf := make([]byte, 16)

	w := NewWriterHTSize(&wbuf, 512, 32)
	r := NewReader(&rbuf)

	f.Fuzz(func(t *testing.T, p0, p1, p2 []byte) {
		w.Reset(w.Writer)
		wbuf.Reset()

		for _, p := range [][]byte{p0, p1, p2} {
			n, err := w.Write(p)
			assert.NoError(t, err)
			assert.Equal(t, len(p), n)
		}

		r.ResetBytes(wbuf.Bytes())
		rbuf.Reset()

		m, err := io.CopyBuffer(&rbuf, r, buf)
		assert.NoError(t, err)
		assert.Equal(t, len(p0)+len(p1)+len(p2), int(m))

		i := 0
		for _, p := range [][]byte{p0, p1, p2} {
			assert.Equal(t, p, rbuf.Bytes()[i:i+len(p)])
			i += len(p)
		}

		assert.Equal(t, int(m), i)

		if !t.Failed() {
			return
		}

		for i, p := range [][]byte{p0, p1, p2} {
			t.Logf("p%d\n%s", i, hex.Dump(p))
		}

		t.Logf("encoded dump\n%s", Dump(wbuf.Bytes()))
	})
}

func (c *ByteCounter) Write(p []byte) (n int, err error) {
	n = len(p)
	*c += ByteCounter(len(p))

	return
}

func nextIndex(st int, b []byte, s ...[]byte) (i int) {
	for i = st; i < len(b); i++ {
		for _, s := range s {
			if i+len(s) < len(b) && bytes.Equal(b[i:i+len(s)], s) {
				return i
			}
		}
	}

	return i
}

func min(x, y int) int {
	if x < y {
		return x
	}

	return y
}