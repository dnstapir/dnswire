# Security

`dnswire` parses untrusted DNS messages. `Parse` is designed and verified to
be safe on adversarial binary input. This document summarizes its guarantees,
resource characteristics, and verification. Last full audit: 2026-08-28.

## Guarantees

On any input, `Parse`:

- never panics, never modifies the input, and never retains references to it;
- runs in a single pass, with work and memory linear in the input size;
- returns errors wrapping only the stable identities `ErrMalformed` and
  `ErrUnsupportedLabel`, always alongside a zero `Message`;
- is deterministic: equal input yields an equal result.

Enforced limits:

- messages larger than 65535 octets are rejected before parsing;
- labels are limited to 63 octets and expanded names to 255 wire octets
  (compression included), so a decoded presentation name is at most 1020
  octets;
- the question count is validated against the octets actually present.

Compression pointers are resolved in constant time against a table of
previously decoded label boundaries, so pointer loops are structurally
impossible and pointer chains cannot amplify work. A pointer that points
forward, at itself, into a label's interior, into the header, or into the
name currently being decoded is rejected as malformed; every such target is
illegal under RFC 1035 section 4.1.4, which requires "a prior occurrence of
the same name".

## Decode completeness

Within its scope (header and question section), no legal encoding is known to
be rejected or decoded incorrectly, including legacy RFC 2673 binary
(bit-string) labels. Messages that `Parse` rejects but lenient parsers accept
were adjudicated case by case during the audit; all were spec-illegal
(truncated question fields, or compression pointers into bytes that are not a
prior name occurrence).

## Resource characteristics

A maximally hostile 65535-octet message can legally expand to roughly 8 MB of
transient decoded name strings (about a 125x amplification) — the inherent
worst case of RFC 1035 compression combined with presentation escaping. The
expansion is bounded, linear, and regression-tested
(`TestParseWorstCaseCompressionAmplification`). `Parse` decodes every question
before returning, so callers wanting a stricter limit must enforce it before
calling `Parse`, by reading the question count directly from the raw message
(the big-endian 16-bit word at octets 4 and 5).

## Verification

- `go test -race` with 100% statement coverage, including adversarial
  regression tests for pointer and length edge cases.
- Three fuzz targets (`FuzzParse`, `FuzzParseOrdinaryName`,
  `FuzzParseHistoricBitString`) enforcing stable error identities, zero
  `Message` on error, input immutability, absolute names within the
  1020-octet presentation bound, question-count agreement, and determinism.
  The audit ran roughly 250 million executions without a failure.
- An independent legal-message oracle and a differential comparison against
  miekg/dns v1 in `benchmarks/differential_test.go` (living in the
  `benchmarks` module keeps the parser module dependency-free). The audit ran
  4.28 million generated legal messages and about 25 million mutated messages
  with zero divergences. A deterministic slice of both runs in CI, and
  `FuzzParseDifferential` supports longer local runs.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub security advisories
("Report a vulnerability" under the repository's Security tab).
