[![Documentation](https://pkg.go.dev/badge/tlog.app/go/eazy)](https://pkg.go.dev/tlog.app/go/eazy?tab=doc)
[![Go workflow](https://github.com/tlog-dev/eazy/actions/workflows/go.yml/badge.svg)](https://github.com/tlog-dev/eazy/actions/workflows/go.yml)
[![CircleCI](https://circleci.com/gh/tlog-dev/eazy.svg?style=svg)](https://circleci.com/gh/tlog-dev/eazy)
[![codecov](https://codecov.io/gh/tlog-dev/eazy/tags/latest/graph/badge.svg)](https://codecov.io/gh/tlog-dev/eazy)
[![Go Report Card](https://goreportcard.com/badge/tlog.app/go/eazy)](https://goreportcard.com/report/tlog.app/go/eazy)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/tlog-dev/eazy?sort=semver)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Ftlog-dev%2Feazy.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Ftlog-dev%2Feazy?ref=badge_shield)

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

Similar sequences are searched in the last `block size` bytes of the data stream. This is similar to block size in snappy or lz4 algorithm.

Stream is started with `eazy.Magic` so the format can be detected.

Multiple streams can be safely concatenated. Zero bytes padding may also be safely added.

## Usage

```
func CompressingWriter(w io.Writer) io.Writer {
	return eazy.NewWriter(w, eazy.MiB, 1024) // block and hash table sizes must be a power of two
}

func DecompressingReader(r io.Reader) io.Reader {
	return eazy.NewReader(r)
}
```


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Ftlog-dev%2Feazy.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Ftlog-dev%2Feazy?ref=badge_large)