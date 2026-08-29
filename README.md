[![build](https://github.com/dnstapir/dnswire/actions/workflows/build.yml/badge.svg)](https://github.com/dnstapir/dnswire/actions/workflows/build.yml)
[![coverage](https://github.com/dnstapir/dnswire/blob/gitcoverage/main/badge.svg)](https://html-preview.github.io/?url=https://github.com/dnstapir/dnswire/blob/gitcoverage/main/report.html)
[![Docs](https://godoc.org/github.com/dnstapir/dnswire?status.svg)](https://godoc.org/github.com/dnstapir/dnswire)

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
for question := range message.Questions {
	fmt.Println(question.Name, question.Type, question.Class)
}
```

## Scope

`Message.Unpack` validates the 12-byte header and complete question section;
`Parse` is shorthand for it on a new `Message`. Neither inspects or validates
answer, authority, or additional records.

`Message.Question` holds the first question. `Message.Questions` enumerates
the complete question section in wire order. `Question.Labels` iterates a
name's presentation-form labels without allocating, and `NextLabel` is a
drop-in for the miekg/dns function of the same name.

Input is limited to 65535 octets. Parsing checks every offset and length,
enforces the 63-octet label and 255-octet expanded-name limits, rejects
forward or invalid compression targets, and returns no partial result.

RFC 6891 deprecates RFC 2673 binary labels and forbids generating or passing
them. This package decodes but does not generate them.

## Differences from miekg/dns

`dnswire` decodes only the header and question section and is built for
adversarial input; miekg/dns v1 and v2 are full message codecs. As observed
against miekg/dns v1.1.72 and v2 v0.6.101:

- **Name fidelity.** `dnswire` and v1 both decode question names to RFC 1035
  presentation format preserving every octet and label boundary, with
  slightly different but equally legal escape sets. v2 intentionally does not
  decode legacy QNAMEs, and its presentation names may be lossy.
- **Legacy labels.** `dnswire` decodes historic RFC 2673 binary (bit-string)
  labels; v1 and v2 reject them.
- **Truncated questions.** `dnswire` rejects a question whose type or class
  is cut off; v1 and v2 accept it, with v1 returning zero values for the
  missing fields.
- **Compression pointers.** `dnswire` follows a pointer only to a prior label
  boundary it has already decoded, as RFC 1035 section 4.1.4 requires; v1 and
  v2 follow any backward pointer, including into the header or a label's
  interior.
- **Message size.** `dnswire` rejects input over the 65535-octet DNS message
  limit up front; v1 and v2 accept oversized input.
- **Errors.** `dnswire` reports every failure through the matchable
  sentinels `ErrMalformed` and `ErrUnsupportedLabel` and leaves a zero
  `Message` on any error.

`benchmarks/differential_test.go` cross-checks `dnswire` against v1 on
generated legal messages and random mutations of them; whenever both accept a
message they must decode identical questions.

## Security

`Unpack` is designed for adversarial input. [SECURITY.md](SECURITY.md)
describes its guarantees, resource characteristics, and verification.

## Benchmarks

The `benchmarks` module uses the miekg/dns versions used by EDM. The parser
module uses only the standard library.

```sh
cd benchmarks
go test -run=^$ -bench=. -benchmem -count=10
```

The v2 benchmark intentionally accepts its lossy presentation name and
measures its normal question-only decoding path. V1 has no question-only
option, so every benchmark packet declares zero answer, authority, and
additional records; its full-message unpacker therefore decodes the same
wire sections. Each implementation receives a fresh message value and
identical input bytes. Each benchmark consumes the message ID, the first
question's name, type, and class, and the total question count.

Results recorded 2026-08-29 with Go 1.27.0 on darwin/arm64 (Apple M5 Max),
using miekg/dns v1.1.72 and v2 v0.6.101. Times are medians of ten runs.

| Input | Parser | ns/op | B/op | allocs/op |
| --- | --- | ---: | ---: | ---: |
| Typical | dnswire | 22.39 | 16 | 1 |
| Typical | miekg/dns v1 | 55.17 | 40 | 2 |
| Typical | miekg/dns v2 | 48.06 | 80 | 3 |
| Unusual legal octets | dnswire | 30.70 | 48 | 1 |
| Unusual legal octets | miekg/dns v1 | 66.86 | 72 | 2 |
| Unusual legal octets | miekg/dns v2 | 46.28 | 88 | 3 |
| Three compressed questions | dnswire | 105.60 | 72 | 3 |
| Three compressed questions | miekg/dns v1 | 137.10 | 208 | 6 |
| Three compressed questions | miekg/dns v2 | 140.85 | 296 | 9 |
