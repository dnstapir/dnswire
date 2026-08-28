[![build](https://github.com/linkdata/dnswire/actions/workflows/build.yml/badge.svg)](https://github.com/linkdata/dnswire/actions/workflows/build.yml)
[![coverage](https://github.com/linkdata/dnswire/blob/gitcoverage/main/badge.svg)](https://html-preview.github.io/?url=https://github.com/linkdata/dnswire/blob/gitcoverage/main/report.html)
[![Docs](https://godoc.org/github.com/linkdata/dnswire?status.svg)](https://godoc.org/github.com/linkdata/dnswire)

# dnswire

`dnswire` is a small Go parser for the DNS header and question section.

It decodes every question name without losing label boundaries or octets:

- ordinary labels use RFC 1035 presentation escaping;
- RFC 1035 compression pointers are resolved only to prior label boundaries;
- historic RFC 2673 bit-string labels are rendered as hexadecimal bit strings;
- unknown extended label types are rejected explicitly.

The parser package uses only the standard library and exposes DNS type and
class values as `uint16`, so callers can compare them directly with constants
from either `codeberg.org/miekg/dns` v2 or `github.com/miekg/dns` v1.

```go
message, err := dnswire.Parse(packet)
if err != nil {
	return err
}
for _, question := range message.Questions {
	fmt.Println(question.Name, question.Type, question.Class)
}
```

## Scope

`Parse` validates the 12-byte header and complete question section. It does
not inspect or validate answer, authority, or additional records.

Input is limited to 65535 octets. Parsing checks every offset and length,
enforces the 63-octet label and 255-octet expanded-name limits, rejects
forward or invalid compression targets, and returns no partial result.

RFC 6891 deprecates RFC 2673 binary labels and forbids generating or passing
them. Decoding remains supported for historical captures; this package does
not generate DNS messages.

## Benchmarks

Comparative benchmarks use the miekg/dns versions used by EDM. These are
benchmark-only dependencies; the parser package imports neither version.

The typical input is one question with an uncompressed name that needs no
presentation escaping. [RFC 9619](https://www.rfc-editor.org/rfc/rfc9619.html)
limits ordinary QUERY messages to at most one question. A
[26-billion-query-pair measurement](https://users.cs.northwestern.edu/~ychen/Papers/DNS_ToN15.pdf)
found bytes outside the alphanumeric-and-hyphen class in 0.2% of queries at
global recursive resolvers. Names needing presentation escaping are a subset
of that group; this parser still accepts and losslessly escapes those legal
octets.

```sh
go test -run=^$ -bench=. -benchmem -count=10
```

The v2 benchmark intentionally accepts its lossy presentation name and
measures its normal question-only decoding path. V1 has no question-only
option, so every benchmark packet declares zero answer, authority, and
additional records; its full-message unpacker therefore decodes the same
wire sections. Each implementation receives a fresh message value and
identical input bytes. Each benchmark consumes the message ID, the first
question's name, type, and class, and the total question count.

Results recorded 2026-08-28 with Go 1.27.0 on darwin/arm64 (Apple M5 Max),
using miekg/dns v1.1.72 and v2 v0.6.101. Times are medians of ten runs.

| Input | Parser | ns/op | B/op | allocs/op |
| --- | --- | ---: | ---: | ---: |
| Typical | dnswire | 37.63 | 40 | 2 |
| Typical | miekg/dns v1 | 54.51 | 40 | 2 |
| Typical | miekg/dns v2 | 47.41 | 80 | 3 |
| Unusual legal octets | dnswire | 40.74 | 72 | 2 |
| Unusual legal octets | miekg/dns v1 | 66.61 | 72 | 2 |
| Unusual legal octets | miekg/dns v2 | 46.97 | 88 | 3 |
| Three compressed questions | dnswire | 110.6 | 104 | 3 |
| Three compressed questions | miekg/dns v1 | 139.3 | 208 | 6 |
| Three compressed questions | miekg/dns v2 | 138.5 | 296 | 9 |
