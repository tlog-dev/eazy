# Stream Format Description

Format is indended to compress logger output. Which leads to the following considerations. 

- Each portion of data given to the encoder must be compressed immediately and written to the underlaying writer.
- Algorithm must be simple (reliable) to not break the using program. And it must be efficient to not limit using program performance.
- The idea is that log messages are frequently only differ slightly.
- Repeating sequences are typically up to 379 bytes long.
- Non-repeating sequences are typically up to 16 bytes long and up to infinity if stream can't be compressed.

Snappy (based on LZ4) uses suitable algorithm.
But it's optimized for general use case where literals and repeating sequences are short.
It also designed to compress data by large blocks, so it adds block header to each portion of output data,
and it looks for repeating sequences inside single block only.

There are no frames or blocks. Stream consists of elements. There are two main types of elements: literal and copy.
Literal is an uncompressed sequence of bytes.
Copy is a reference to a sequence of bytes that was seen previously in the stream.
Copy can reference data in at most `window size` bytes back.

## Tag

Both elements start from a tag and a length. Tag is the highest (the most significant) bit of the first byte of the element.
Tag `0<<7` means literal and tag `1<<7` means copy.

Length is encoded shorter for lower values and a bit longer for larger values.
First `123` (`Len1 - 1`, where `Len1 = 128 - 4`) values encoded in `7` lower bits of the first byte.

Next `256 [Len1+0 .. Len1+256)` values encoded as the special value `Len1` in the first byte
and `value - Len1` in the next byte.

Next `2^16` values encoded as a special value `Len2 (128 - 3)`
and the value minus `maximum representeble number in Len1 case` in the following two bytes in the little endian order.

The code says better.
```
// Tags.
const (
	Literal = iota << 7
	Copy

	TagMask    = 0b1000_0000
	TagLenMask = 0b0111_1111
)

// Tag lengths.
const (
	_ = 1<<7 - iota
	Len8 // deprecated
	Len4
	Len2
	Len1
)
```

Length encoder.

```
if l < Len1 {
	return []byte{byte(l)}
}

l -= Len1

if l < 0x100 {
	return []byte{Len1, byte(l)}
}

l -= 0x100

if l < 0x10000 {
	return []byte{Len2, byte(l), byte(l >> 8)}
}

l -= 0x10000

// ...
```

Few examples.

```
[]byte{Literal | 16}               // 0x10       // Literal tag with the length of 16
[]byte{Literal | Len1-1}           // 0x7b       // Literal tag with the length of 123
[]byte{Literal | Len1, 255 - Len1} // 0x7c 0x83  // Literal tag with the length of 255
[]byte{Copy | Len1, 379 - Len1}    // 0x7c 0xff  // Copy tag with the length of 379
[]byte{Copy | Len2, 0, 0}          // 0x7d 0x00 0x00  // Copy tag with the length of 380
[]byte{Copy | Len2, 1, 0}          // 0x7d 0x01 0x00  // Copy tag with the length of 381
```

Decoding happens with the same logic. Say we have buffer `b` with compressed data and we start from index `i`.

```
tag := b[i] & TagMask
l := int(b[i] & TagLenMask) // length

switch {
case l < Len1:
	// we are fine
case l == Len1:
	l = Len1 + int(b[i+1])
case l == Len2:
	l = Len1 + 0x100
	l += int(b[i+1]) | int(b[i+2])<<8
case l == Len4:
	// ...
}
```

## Literal

Literal tag is followed by `length` bytes which are copied to the output buffer directly.

```
[]byte{Literal | 3, 'a', 'b', 'c'} // "abc"
```

## Copy

Copy tag is followed by offset, which is encoded much like length, but it have 8 bits in the first byte to use.

```
// Offset lengths.
const (
	_ = 1<<8 - iota
	Off8 // deprecated
	Off4
	Off2
	Off1

	OffLong = Off8
)

[]byte{1}          // 0x01           // 1
[]byte{Off1-1}     // 0xfb           // 251
[]byte{Off1, 0}    // 0xfc 0x00      // 252
[]byte{Off2, 5, 0} // 0xfd 0x05 0x00 // 513
```

As most of our offsets point to past bytes we can store `offset - length` instead.
Which saves a few bytes on offset encoding length.
So we actually store the offset to the byte following the referenced sequence.
And the start of that sequence is found substracting its length from the offset.

```
[]byte{Literal | 5, 'a', 'b', 'c', 'd', 'e', // "abcde"
	Copy | 2, 4-2}                           // "bc"
	// copy 2 bytes from 4 bytes before

[]byte{Literal | 3, 'a', 'b', 'c', // "abc"
	Copy | 2, 0}                   // "bc"
	// copy the two latest decoded bytes
```

That way we save some bytes on back references but we can't encode runlen sequence (sequence of the same symbols repeated multiple times).

```
"abcd" + "bcd" + "bcd" + "bcd"
```

It could be encoded as `"abcd"` literal and `copy 9 bytes starting from the 3 bytes before`.

If we followed the same algorithm encoded offset would be a negative number (`3 - 9`).
So the little bit other approach is used.
`Off8` is deprecated so the same value is reused as `OffLong`, which means long offset,
which in turn means offset to the beginning of the value, not to its end.

So the last case encoded as
```
[]byte{Literal | 4, 'a', 'b', 'c', 'd',
	Copy | 9, OffLong, 3}
```

As copying from offset 0 doesn't make much sence it's used as a special case to encode zero bytes.
Logically we copy not yet written byte from output stream which is consider is x00.

```
[]byte{Copy | 15, OffLong, 0} // emit 15 zero bytes
```

## Meta

It's super nice we use only one bit for a tag so we can encode length values up to `123` in the same byte.
But we also need to encode some out of band information.

First, we want to have a Magic bytes sequence in the beginning of the stream to be able to detect it.

Second, we want to have format version, so that we can improve it in the future or fix a bug being able to read old streams.

Third, we want to be able to use different window sizes where copy offsets are pointing to.
Window size should be chosen from the data we are compressing.
The further repeating sequences from each other in the stream, the longer should be the window to compress them.
But in the same time it requires more memory both on encoder and decoder side.
Encoder and decoder must use the same window size and it must be known in advance.
And we want to have it embedded in the stream itself.

More meta tags may be added in future, checksum for example.

Meta tags are rare, they are basically appear once in a stream, so we don't want to sacrifice main tags for that.
Copy tag with zero length doesn't make much sence, so we use it as Meta tag marker.
When it's decoded from the stream, the next bytes are interpreted as a meta tag.

Meta tag consists of two parts: tag itsef (5 higher bits) and its content length (3 lower bits).
Length is encoded as log2(data). `1<<length` following bytes are meta tag data.

```
// Meta tags.
const (
	// len: 1 2 4 8  16 32 64 LenWide

	MetaMagic = iota << 3 // 4: "eazy"
	MetaVer               // 1: ver
	MetaReset             // 1: block_size_log2

	MetaTagMask = 0b1111_1000 // tag | log(size)
	MetaLenMask = 0b0000_0111
	MetaLenWide = MetaLenMask
)

[]byte{Copy | 0, MetaMagic | 2, 'e', 'a', 'z', 'y'} // eazy magic sequence // encoded data size is 2, which decodes to 1<<2 == 4 bytes
[]byte{Copy | 0, MetaVer | 0, 1}                    // format version      // encoded data size is 0, which decodes to 1<<0 == 1 byte
[]byte{Copy | 0, MetaReset | 0, 20}                 // window size: 1<<20  // 1 MiB (1_048_576 bytes)
```

## Padding

The last tag we want to have is padding. We want this to be able to have compressed large files with kinda random access available.
Compressed stream can only be parsed from the beginning as we need to have previous bytes decoded to decode next ones.
But we can concatenate multiple streams into the same file.
That concatenated stream can be decoded sequetially or starting from any chunk in the middle.
In some situations we may want to align chunks to some value, 32MiB for example.
This is where padding kicks in.

Padding is encoded as `0x00` byte. Which is decoded as zero length literal followed by an empty sequence of bytes.

## Overhead

Magic is optional, but Version and Reset meta tags are required to decode the stream.
Thus at least `6` bytes of overhead is added to the stream. `12` if Magic is used.
Literals up to `123` bytes long require only one byte of overhead.
Copy elements takes `2` to `5` bytes in most cases which is enough to encode up to `378` bytes copied from `~66KB` back.
