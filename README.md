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

```sh
go test -run=^$ -bench=. -benchmem
```

The v2 benchmark intentionally accepts its lossy presentation name and
measures its normal question-only decoding path. V1 has no question-only
option, so every benchmark packet declares zero answer, authority, and
additional records; its full-message unpacker therefore decodes the same
wire sections. Each implementation receives a fresh message value and
identical input bytes. Each benchmark consumes the message ID, the first
question's name, type, and class, and the total question count.
