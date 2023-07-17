[![Documentation](https://pkg.go.dev/badge/github.com/nikandfor/eazy)](https://pkg.go.dev/github.com/nikandfor/eazy?tab=doc)
[![Go workflow](https://github.com/nikandfor/eazy/actions/workflows/go.yml/badge.svg)](https://github.com/nikandfor/eazy/actions/workflows/go.yml)
[![codecov](https://codecov.io/gh/nikandfor/eazy/tags/latest/graph/badge.svg)](https://codecov.io/gh/nikandfor/eazy)
[![Go Report Card](https://goreportcard.com/badge/github.com/nikandfor/eazy)](https://goreportcard.com/report/github.com/nikandfor/eazy)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/nikandfor/eazy?sort=semver)

# eazy

eazy is a compression algorithm, file format, and library. And it's designed specially for logging.
It uses very similar compression algorithm as snappy and LZ4.

The main difference is that snappy and LZ4 buffer data and compress it by blocks.
eazy on the other hand compresses each individual `Write` and writes it to the underlaying `io.Writer` immediately.
So one `eazy.Writer.Write(uncopressed)` results in exactly one `underlayingWriter.Write(compressed)`.

That means no data will be lost in case of panic or if the app has been killed.

Compression is based on the idea that logs contain repeating sequences of bytes,
such as constant log messages, trace ids, keys in key-value pairs, similar values logged multiple times (client ip, request path).
Repeating parts are encoded as pairs of length and offset of the previous occurrence.

Writer block size is the latest stream part size where similar sequences are searched.
Repeating similar messages should be at most block size far from each other to be better compressed.

Stream is started with `eazy.FileMagic` so the file format can be detected.

Multiple streams can be safely concatenated.

## Usage

```
func CompressingWriter(w io.Writer) io.Writer {
	return eazy.NewWriter(w, eazy.MiB) // block size must be a power of two
}

func DecompressingReader(r io.Reader) io.Reader {
	return eazy.NewReader(r)
}
```
