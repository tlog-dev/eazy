package eazy

import (
	"bytes"
	"encoding/hex"
	"flag"
	"io"
	"os"
	"testing"
	"time"

	//	"github.com/nikandfor/assert"
	"github.com/nikandfor/hacked/low"
	"github.com/stretchr/testify/assert"
	"tlog.app/go/errors"
)

type (
	ByteCounter int64
)

var (
	fileFlag       = flag.String("test-file", "log.tlog", "file with tlog logs")
	ratioEstimator = flag.Int("ratio-estimator", 0, "ratio estimator iterations to run")
)

var (
	testData   []byte
	testOff    []int
	testsCount int
)

func TestFileMagic(t *testing.T) {
	var buf low.Buf

	w := NewWriter(&buf, MiB, 512)

	_, err := w.Write([]byte{})
	assert.NoError(t, err)

	if assert.True(t, len(buf) >= len(FileMagic)) {
		assert.Equal(t, FileMagic, string(buf[:len(FileMagic)]))
	}

	t.Logf("file header:\n%s", hex.Dump(buf))
}

func TestLiteral(t *testing.T) {
	t.Run("ver0", func(t *testing.T) { testLiteral(t, 0) })
	t.Run("ver1", func(t *testing.T) { testLiteral(t, 1) })
}

func testLiteral(t *testing.T, ver int) {
	const B = 32

	var buf low.Buf

	w := NewWriter(&buf, B, B>>1)
	w.ver = ver

	n, err := w.Write([]byte("very_first_message"))
	assert.Equal(t, 18, n)
	assert.NoError(t, err)

	t.Logf("buf pos %x  ht %x  block\n%v", w.pos, w.ht, hex.Dump(w.block))
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
	t.Run("ver0", func(t *testing.T) { testCopy(t, 0) })
	t.Run("ver1", func(t *testing.T) { testCopy(t, 1) })
}

func testCopy(t *testing.T, ver int) {
	const B = 32

	var buf low.Buf

	w := NewWriter(&buf, B, B>>1)
	w.ver = ver

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

	t.Logf("res\n%v", Dump(buf))

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

	_, _ = b.Write([]byte{Meta, MetaReset | 0, 4}) //nolint:staticcheck
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

func TestPadding(t *testing.T) {
	const B = 32

	var buf low.Buf

	w := NewWriter(&buf, B, B>>1)

	st := 0

	n, err := w.Write([]byte("prefix_1234_suffix"))
	assert.Equal(t, 18, n)
	assert.NoError(t, err)

	t.Logf("buf pos %x ht %x\n%v", w.pos, w.ht, hex.Dump(w.block))
	t.Logf("res\n%v", hex.Dump(buf[st:]))

	st = len(buf)

	buf = append(buf, make([]byte, B-len(buf)%B)...)

	n, err = w.Write([]byte("prefix_567_suffix"))
	assert.Equal(t, 17, n)
	assert.NoError(t, err)

	t.Logf("buf  pos %x ht %x\n%v", w.pos, w.ht, hex.Dump(w.block))
	t.Logf("res\n%v", hex.Dump(buf[st:]))

	t.Logf("res\n%v", Dump(buf))

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

func TestOnFile(t *testing.T) {
	t.Run("ver0", func(t *testing.T) { testOnFile(t, 0) })
	t.Run("ver1", func(t *testing.T) { testOnFile(t, 1) })
}

func testOnFile(t *testing.T, ver int) {
	err := loadTestFile(t, *fileFlag)
	if err != nil {
		t.Skipf("loading data: %v", err)
	}

	var enc low.BufReader
	var buf []byte

	w := NewWriter(&enc, 1024, 512)
	w.ver = ver

	r := NewReader(&enc)

	var dumpb low.Buf

	d := NewDumper(nil)

	for i := 0; i < testsCount; i++ {
		msg := testData[testOff[i]:testOff[i+1]]

		wst := len(enc.Buf)

		n, err := w.Write(msg)
		assert.NoError(t, err)
		assert.Equal(t, len(msg), n)

		for n > cap(buf) {
			buf = append(buf[:cap(buf)], 0, 0, 0, 0, 0, 0, 0, 0)
		}

		n, err = r.Read(buf[:n])
		assert.NoError(t, err)
		assert.Equal(t, len(msg), n)

		assert.Equal(t, msg, buf[:n])

		if t.Failed() {
			d.Writer = &dumpb
		}

		_, _ = d.Write(enc.Buf[wst:])

		if t.Failed() {
			t.Logf("msg %d encoded dump:\n%s", i, dumpb)
			break
		}
	}

	enc.R = 0

	var dec low.Buf

	n, err := io.Copy(&dec, r)
	assert.NoError(t, err)
	assert.Equal(t, int(n), dec.Len())

	min := dec.Len()
	assert.Equal(t, testData[:min], dec.Bytes())

	//	t.Logf("metrics: %v  bytes %v  events %v", mm, dec.Len(), testsCount)
	t.Logf("compression ratio %v", dec.LenF()/enc.Buf.LenF())
}

func TestOnFileRatioEstimator(t *testing.T) {
	if *ratioEstimator == 0 {
		t.Skipf("set --ratio-estimator=N to run, N is number of iterations")
	}

	err := loadTestFile(t, *fileFlag)
	if err != nil {
		t.Skipf("loading data: %v", err)
	}

	N := *ratioEstimator

	var buf low.Buf
	w := NewWriter(&buf, 1024, 16)

	for bs := 4 * 1024; bs <= 4*1024*1024; bs <<= 1 {
		lastRatio := 0.

		for hs := 64; hs <= 64*1024; hs <<= 1 {
			st := time.Now()

			for n := 0; n < N; n++ {
				buf.Reset()
				w.ResetSize(&buf, bs, hs)

				for i := 0; i < testsCount; i++ {
					msg := testData[testOff[i]:testOff[i+1]]

					_, err := w.Write(msg)
					if err != nil {
						t.Errorf("write: %v", err)
						return
					}
				}
			}

			d := time.Since(st)

			ratio := float64(len(testData)) / buf.LenF()
			speed := float64(len(testData)) * float64(N) / (1 << 20) / d.Seconds()

			t.Logf("block %7d  htable %7d  ratio %5.1f  speed %7.1f MBps  written %6d events  %8d bytes  compressed size %8d bytes",
				bs, hs, ratio, speed, testsCount, len(testData), buf.Len())

			if ratio < lastRatio*1.01 && ratio > 2 {
				break
			}

			lastRatio = ratio
		}
	}
}

const BlockSize, HTSize = 1024 * 1024, 2 * 1024

func BenchmarkCompressFile(b *testing.B) {
	err := loadTestFile(b, *fileFlag)
	if err != nil {
		b.Skipf("loading data: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	var c ByteCounter
	w := NewWriter(&c, BlockSize, HTSize)

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
	w := NewWriter(&encoded, BlockSize, HTSize)

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

	w := NewWriter(&wbuf, 512, 32)
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
