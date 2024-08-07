//go:build csv_dumper

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"tlog.app/go/eazy"
)

type Buf []byte

var (
	infile  = flag.String("i", "", "eazy compressed input file")
	outfile = flag.String("o", "", "output csv file")
	header  = flag.Bool("h", true, "add header row")
	base    = flag.Int("base", 10, "offset and length base")
	data    = flag.Int("data", 0, "data max len")
)

func main() {
	flag.Parse()

	err := run()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
}

func run() (err error) {
	var fr io.Reader

	if q := *infile; q != "" && q != "-" {
		f, err := os.Open(q)
		if err != nil {
			return fmt.Errorf("open input file: %w", err)
		}

		defer func() {
			e := f.Close()
			if err == nil {
				err = fmt.Errorf("close input file: %w", e)
			}
		}()

		fr = f
	} else {
		fr = os.Stdin
	}

	var fw io.Writer

	if q := *outfile; q != "" && q != "-" {
		f, err := os.Create(q)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}

		defer func() {
			e := f.Close()
			if err == nil {
				err = fmt.Errorf("close output file: %w", e)
			}
		}()

		fw = f
	} else {
		fw = os.Stdout
	}

	if *header {
		_, err = fw.Write([]byte("ioff,iend,ooff,tag,l,off\n"))
		if err != nil {
			return fmt.Errorf("write header")
		}
	}

	var b Buf

	d := eazy.NewDumper(nil)

	d.Debug = func(ioff, iend, ooff int64, tag byte, l, off int) {
		b = b[:0]

		b = strconv.AppendInt(b, ioff, *base)
		b = append(b, ',')

		b = strconv.AppendInt(b, iend, *base)
		b = append(b, ',')

		b = strconv.AppendInt(b, ooff, *base)
		b = append(b, ',')

		b = fmt.Appendf(b, "%c,", tag)

		b = strconv.AppendInt(b, int64(l), *base)
		b = append(b, ',')

		if tag == 'm' {
			off >>= 3
		}

		b = strconv.AppendInt(b, int64(off), *base)
		b = append(b, '\n')

		_, _ = fw.Write(b)

		//	fmt.Fprintf(fw, "%d,%d,%c,%d,%d\n", ioff, ooff, tag, l, off)
	}

	_, err = io.Copy(d, fr)
	if err != nil {
		return fmt.Errorf("copy: %w", err)
	}

	return nil
}
