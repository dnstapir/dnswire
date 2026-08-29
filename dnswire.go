// Package dnswire parses DNS headers and question sections.
package dnswire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

// HeaderSize is the size of a DNS message header in octets.
const HeaderSize = 12

const (
	maxMessageSize          = 1<<16 - 1
	maxNameWireSize         = 255
	maxNamePresentationSize = 4 * maxNameWireSize
)

var (
	// ErrMalformed reports an invalid DNS header or question section.
	ErrMalformed = errors.New("dnswire: malformed DNS message")

	// ErrUnsupportedLabel reports a DNS label type the parser cannot decode.
	ErrUnsupportedLabel = errors.New("dnswire: unsupported DNS label type")
)

// Header contains the six 16-bit words in a DNS message header.
type Header struct {
	ID              uint16
	Flags           uint16
	QuestionCount   uint16
	AnswerCount     uint16
	AuthorityCount  uint16
	AdditionalCount uint16
}

// Response reports whether the QR flag is set: the message is a response.
func (header Header) Response() bool { return header.Flags&(1<<15) != 0 }

// Opcode returns the 4-bit OPCODE field: the kind of query in the message.
func (header Header) Opcode() int { return int(header.Flags >> 11 & 0xf) }

// Authoritative reports whether the AA flag is set: the responding server is
// an authority for the domain name in the question section.
func (header Header) Authoritative() bool { return header.Flags&(1<<10) != 0 }

// Truncated reports whether the TC flag is set: the message was truncated.
func (header Header) Truncated() bool { return header.Flags&(1<<9) != 0 }

// RecursionDesired reports whether the RD flag is set: the sender asks the
// server to pursue the query recursively.
func (header Header) RecursionDesired() bool { return header.Flags&(1<<8) != 0 }

// RecursionAvailable reports whether the RA flag is set: the server supports
// recursive queries.
func (header Header) RecursionAvailable() bool { return header.Flags&(1<<7) != 0 }

// Zero reports whether the reserved Z bit is set.
func (header Header) Zero() bool { return header.Flags&(1<<6) != 0 }

// AuthenticatedData reports whether the AD flag is set: all data in the
// response has been cryptographically verified (RFC 4035).
func (header Header) AuthenticatedData() bool { return header.Flags&(1<<5) != 0 }

// CheckingDisabled reports whether the CD flag is set: the sender accepts
// unverified data (RFC 4035).
func (header Header) CheckingDisabled() bool { return header.Flags&(1<<4) != 0 }

// Rcode returns the 4-bit RCODE field: the response code.
//
// EDNS0 extended RCODE bits live in the additional section, which this
// package does not decode.
func (header Header) Rcode() int { return int(header.Flags & 0xf) }

// Question contains one decoded DNS question.
type Question struct {
	// Name is an absolute RFC presentation-format domain name.
	Name  string
	Type  uint16
	Class uint16
}

// Labels yields the labels of Name in presentation form, in order and
// without the separating dots; the root name yields nothing.
//
// It allocates nothing. See [NextLabel] for the underlying scan.
func (question Question) Labels(yield func(string) bool) {
	name := question.Name
	if name == "." {
		return
	}
	for start := 0; start < len(name); {
		next, end := NextLabel(name, start)
		if !yield(name[start:next-1]) || end {
			return
		}
		start = next
	}
}

// NextLabel returns the offset of the label following the one that starts at
// offset in the presentation-form name, and whether that label was the last.
//
// It is a drop-in for miekg/dns NextLabel on names this package produces:
// offset must be a label start, an escaped dot never separates labels, and
// the trailing dot of an absolute name is not a separator.
func NextLabel(name string, offset int) (next int, end bool) {
	for i := offset; i < len(name)-1; i++ {
		switch name[i] {
		case '\\':
			// Skip the escaped octet; \DDD digits are never dots.
			i++
		case '.':
			return i + 1, false
		}
	}
	return len(name), true
}

// Message contains a DNS header and its questions.
type Message struct {
	Header        Header
	Question      Question // First question; zero when Header.QuestionCount is zero.
	moreQuestions []Question
}

// Questions yields every decoded question in wire order.
func (message *Message) Questions(yield func(Question) bool) {
	if message.Header.QuestionCount == 0 || !yield(message.Question) {
		return
	}
	for _, question := range message.moreQuestions {
		if !yield(question) {
			return
		}
	}
}

// Parse decodes a DNS header and every question from data.
//
// It is shorthand for [Message.Unpack] on a new Message, discarding the
// consumed-octet count.
func Parse(data []byte) (message Message, err error) {
	_, err = message.Unpack(data)
	return
}

// Unpack decodes a DNS header and every question from data into message,
// overwriting it entirely, and returns the number of octets consumed: the
// header plus the complete question section, so records begin at data[n:].
//
// Names use RFC 1035 presentation escaping, preserving every ordinary-label
// octet and every label boundary. Historic RFC 2673 bit-string labels use
// their hexadecimal presentation form. Compression pointers must refer to a
// previously decoded label boundary.
//
// Unpack does not inspect or validate answer, authority, or additional
// sections. On error it leaves a zero Message and returns a zero count. It
// never retains data.
func (message *Message) Unpack(data []byte) (n int, err error) {
	*message = Message{}
	if len(data) < HeaderSize {
		err = malformed(len(data), "header is shorter than 12 octets")
		return
	}
	if len(data) > maxMessageSize {
		err = malformed(maxMessageSize, "message exceeds 65535 octets")
		return
	}

	message.Header = Header{
		ID:              binary.BigEndian.Uint16(data[0:2]),
		Flags:           binary.BigEndian.Uint16(data[2:4]),
		QuestionCount:   binary.BigEndian.Uint16(data[4:6]),
		AnswerCount:     binary.BigEndian.Uint16(data[6:8]),
		AuthorityCount:  binary.BigEndian.Uint16(data[8:10]),
		AdditionalCount: binary.BigEndian.Uint16(data[10:12]),
	}

	// Each question needs at least a root label octet plus 16-bit type and class.
	questionCount := int(message.Header.QuestionCount)
	if questionCount > (len(data)-HeaderSize)/5 {
		*message = Message{}
		err = malformed(HeaderSize, "question count cannot fit in message")
		return
	}

	var names map[int]nameSuffix
	if questionCount > 1 {
		message.moreQuestions = make([]Question, 0, questionCount-1)
		names = make(map[int]nameSuffix)
	}
	off := HeaderSize
	for i := range questionCount {
		var question Question
		question, off, names, err = unpackQuestion(data, off, names)
		if err != nil {
			*message = Message{}
			err = fmt.Errorf("question %d: %w", i, err)
			return
		}
		if i == 0 {
			message.Question = question
		} else {
			message.moreQuestions = append(message.moreQuestions, question)
		}
	}
	n = off
	return
}

// unpackQuestion decodes one question starting at off.
//
// A nil names marks a single-question message: the ordinary-name fast path
// skips label boundary bookkeeping, and updated stays nil unless the name
// needs the map. Callers pass updated back in for the next question.
func unpackQuestion(data []byte, off int, names map[int]nameSuffix) (question Question, next int, updated map[int]nameSuffix, err error) {
	ordinary := false
	next, updated = off, names
	if updated == nil {
		if question.Name, next, ordinary, err = unpackOrdinaryName(data, off); err != nil {
			return
		}
	}
	if !ordinary {
		if updated == nil {
			updated = make(map[int]nameSuffix)
		}
		if question.Name, next, err = unpackName(data, next, updated); err != nil {
			return
		}
	}
	if next+4 > len(data) {
		err = malformed(next, "question type or class is truncated")
		return
	}
	question.Type = binary.BigEndian.Uint16(data[next : next+2])
	question.Class = binary.BigEndian.Uint16(data[next+2 : next+4])
	next += 4
	return
}

// unpackOrdinaryName decodes a name made solely of ordinary labels, returning
// ordinary false without consuming input when it meets any other label type.
func unpackOrdinaryName(data []byte, start int) (name string, next int, ordinary bool, err error) {
	// An unescaped presentation name is shorter than its wire encoding.
	// Escape-heavy names grow this slice as needed.
	var (
		text       [maxNameWireSize]byte
		rendered   = text[:0]
		wireLength int
		off        = start
	)
	next = start
	ordinary = true

	for {
		if off >= len(data) {
			err = malformed(off, "domain name is not terminated")
			return
		}

		length := data[off]
		if length&0xc0 != 0 {
			ordinary = false
			return
		}
		if length == 0 {
			if len(rendered) == 0 {
				name = "."
			} else {
				name = string(rendered)
			}
			next = off + 1
			return
		}

		labelLength := int(length)
		end := off + 1 + labelLength
		if end > len(data) {
			err = malformed(off, "domain label is truncated")
			return
		}
		wireLength += 1 + labelLength
		if wireLength >= maxNameWireSize {
			err = malformed(start, "domain name exceeds 255 octets")
			return
		}

		rendered = appendEscapedLabel(rendered, data[off+1:end])
		rendered = append(rendered, '.')
		off = end
	}
}

// namePart records one decoded label of a name prefix awaiting completion.
type namePart struct {
	offset     int // wire offset of the label
	wireLength int
	textOffset int // start of this label's text in the rendered name
	bits       int // 0 for an ordinary label, else the RFC 2673 bit count (1-256)
}

// nameSuffix is the fully decoded name at a registered label boundary: its
// presentation text ("" for the root) and expanded wire length.
type nameSuffix struct {
	text       string
	wireLength int
}

// unpackName decodes one name of any supported label types starting at
// start, recording every decoded label boundary in names.
func unpackName(data []byte, start int, names map[int]nameSuffix) (name string, next int, err error) {
	var (
		partBuffer       [4]namePart
		parts            = partBuffer[:0]
		prefixWireLength int
		tail             nameSuffix
		terminalSize     int
		off              = start
	)

scan:
	for {
		if off >= len(data) {
			err = malformed(off, "domain name is not terminated")
			return
		}

		labelOffset := off
		length := data[off]
		switch length & 0xc0 {
		case 0x00:
			if length == 0 {
				tail = nameSuffix{wireLength: 1}
				terminalSize = 1
				break scan
			}

			labelLength := int(length)
			end := off + 1 + labelLength
			if end > len(data) {
				err = malformed(off, "domain label is truncated")
				return
			}
			prefixWireLength += 1 + labelLength
			if prefixWireLength >= maxNameWireSize {
				err = malformed(start, "domain name exceeds 255 octets")
				return
			}
			parts = append(parts, namePart{
				offset:     labelOffset,
				wireLength: 1 + labelLength,
			})
			off = end

		case 0x40:
			if length != 0x41 {
				err = unsupportedLabel(off, length)
				return
			}
			var bits int
			bits, off, err = unpackBitStringLabel(data, off)
			if err != nil {
				return
			}
			wireLength := off - labelOffset
			prefixWireLength += wireLength
			if prefixWireLength >= maxNameWireSize {
				err = malformed(start, "domain name exceeds 255 octets")
				return
			}
			parts = append(parts, namePart{
				offset:     labelOffset,
				wireLength: wireLength,
				bits:       bits,
			})

		case 0xc0:
			if off+1 >= len(data) {
				err = malformed(off, "compression pointer is truncated")
				return
			}
			target := int(length&0x3f)<<8 | int(data[off+1])
			if target >= off {
				err = malformed(off, "compression pointer does not point backward")
				return
			}
			var ok bool
			if tail, ok = names[target]; !ok {
				err = malformed(off, "compression pointer target is not a prior label boundary")
				return
			}
			terminalSize = 2
			break scan

		default:
			err = malformed(off, "unallocated DNS label type")
			return
		}
	}

	// off is the terminal label's offset: neither terminal branch advances it.
	names[off] = tail
	name, err = completeName(data, parts, prefixWireLength, tail, names)
	if err == nil {
		next = off + terminalSize
	}
	return
}

// completeName enforces the expanded-name length limit, renders the prefix
// parts and tail into presentation form, and registers each part's suffix in
// names.
func completeName(data []byte, parts []namePart, prefixWireLength int, tail nameSuffix, names map[int]nameSuffix) (name string, err error) {
	if prefixWireLength > maxNameWireSize-tail.wireLength {
		// prefixWireLength is nonzero only when parts is non-empty.
		err = malformed(parts[0].offset, "domain name exceeds 255 octets")
		return
	}
	if len(parts) == 0 {
		name = tail.text
		if name == "" {
			name = "."
		}
		return
	}
	wireLength := tail.wireLength + prefixWireLength

	var (
		text     [maxNamePresentationSize]byte
		rendered = text[:0]
	)
	for i := range parts {
		part := &parts[i]
		part.textOffset = len(rendered)
		off := part.offset
		if part.bits == 0 {
			labelLength := int(data[off])
			rendered = appendEscapedLabel(rendered, data[off+1:off+1+labelLength])
		} else {
			bits := part.bits
			byteCount := (bits + 7) / 8
			rendered = appendBitStringPresentation(rendered, data[off+2:off+2+byteCount], bits)
		}
		rendered = append(rendered, '.')
	}
	rendered = append(rendered, tail.text...)
	name = string(rendered)

	for _, part := range parts {
		names[part.offset] = nameSuffix{
			text:       name[part.textOffset:],
			wireLength: wireLength,
		}
		wireLength -= part.wireLength
	}
	return
}

// unpackBitStringLabel validates the RFC 2673 bit-string label at off and
// returns its bit count and the offset of the following label.
func unpackBitStringLabel(data []byte, off int) (bits int, next int, err error) {
	if off+1 >= len(data) {
		err = malformed(off, "bit-string label has no bit count")
		return
	}
	bits = int(data[off+1])
	if bits == 0 {
		bits = 256
	}
	byteCount := (bits + 7) / 8
	next = off + 2 + byteCount
	if next > len(data) {
		err = malformed(off, "bit-string label is truncated")
	}
	return
}

// appendBitStringPresentation appends the RFC 2673 hexadecimal presentation
// of a bit-string label to text, masking the unused pad bits.
func appendBitStringPresentation(text, data []byte, bits int) []byte {
	const hexDigits = "0123456789abcdef"
	digitCount := (bits + 3) / 4

	text = append(text, '\\', '[', 'x')
	for i := range digitCount {
		value := data[i/2]
		if i%2 == 0 {
			value >>= 4
		} else {
			value &= 0x0f
		}
		if i == digitCount-1 && bits%4 != 0 {
			value &= 0x0f << (4 - bits%4)
		}
		text = append(text, hexDigits[value])
	}
	text = append(text, '/')
	text = strconv.AppendInt(text, int64(bits), 10)
	return append(text, ']')
}

// escapeNeeded marks the octets RFC 1035 presentation escaping cannot copy
// verbatim: control and non-ASCII octets plus the escaped specials.
var escapeNeeded = func() (table [256]bool) {
	for i := range table {
		table[i] = i < ' ' || i > '~'
	}
	for _, value := range []byte{'.', ' ', '\'', '@', ';', '(', ')', '"', '\\'} {
		table[value] = true
	}
	return
}()

// appendEscapedLabel appends label to text in RFC 1035 presentation form,
// copying it verbatim when no octet needs escaping.
func appendEscapedLabel(text, label []byte) []byte {
	for _, value := range label {
		if escapeNeeded[value] {
			return appendEscapedLabelSlow(text, label)
		}
	}
	return append(text, label...)
}

// appendEscapedLabelSlow appends label to text, escaping specials with a
// backslash and other escape-needing octets as \DDD.
//
// It stays out of line so appendEscapedLabel itself fits the inlining budget.
//
//go:noinline
func appendEscapedLabelSlow(text, label []byte) []byte {
	for _, value := range label {
		switch value {
		case '.', ' ', '\'', '@', ';', '(', ')', '"', '\\':
			text = append(text, '\\', value)
		default:
			if value < ' ' || value > '~' {
				text = append(text, '\\', '0'+value/100, '0'+value/10%10, '0'+value%10)
			} else {
				text = append(text, value)
			}
		}
	}
	return text
}

// malformed returns an error wrapping ErrMalformed located at off.
func malformed(off int, reason string) error {
	return fmt.Errorf("%w at offset %d: %s", ErrMalformed, off, reason)
}

// unsupportedLabel returns an error wrapping ErrUnsupportedLabel for the
// label type octet at off.
func unsupportedLabel(off int, labelType byte) error {
	return fmt.Errorf("%w 0x%02x at offset %d", ErrUnsupportedLabel, labelType, off)
}
