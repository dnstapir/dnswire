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

// Question contains one decoded DNS question.
type Question struct {
	// Name is an absolute RFC presentation-format domain name.
	Name  string
	Type  uint16
	Class uint16
}

// Message contains a DNS header and its questions.
type Message struct {
	Header        Header
	Question      Question // First question; zero when Header.QuestionCount is zero.
	moreQuestions []Question
}

// Questions yields every decoded question in wire order.
func (message Message) Questions(yield func(Question) bool) {
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
// Names use RFC 1035 presentation escaping, preserving every ordinary-label
// octet and every label boundary. Historic RFC 2673 bit-string labels use
// their hexadecimal presentation form. Compression pointers must refer to a
// previously decoded label boundary.
//
// Parse does not inspect or validate answer, authority, or additional
// sections. It returns a zero Message on error and never retains data.
func Parse(data []byte) (message Message, err error) {
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
		message = Message{}
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
			message = Message{}
			err = fmt.Errorf("question %d: %w", i, err)
			return
		}
		if i == 0 {
			message.Question = question
		} else {
			message.moreQuestions = append(message.moreQuestions, question)
		}
	}
	return
}

// unpackQuestion decodes one question starting at off.
//
// A nil names marks a single-question message: the ordinary-name fast path
// skips label boundary bookkeeping, and updated stays nil unless the name
// needs the map. Callers pass updated back in for the next question.
func unpackQuestion(data []byte, off int, names map[int]nameSuffix) (question Question, next int, updated map[int]nameSuffix, err error) {
	ordinary := false
	next = off
	updated = names
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

func unpackOrdinaryName(data []byte, start int) (name string, next int, ordinary bool, err error) {
	// An unescaped presentation name is shorter than its wire encoding.
	// Escape-heavy names grow this slice as needed.
	var text [maxNameWireSize]byte
	rendered := text[:0]
	wireLength := 0
	off := start
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

type namePart struct {
	offset     int // wire offset of the label
	wireLength int
	textOffset int // start of this label's text in the rendered name
	bits       int // 0 for an ordinary label, else the RFC 2673 bit count (1-256)
}

type nameSuffix struct {
	text       string
	wireLength int
}

func unpackName(data []byte, start int, names map[int]nameSuffix) (name string, next int, err error) {
	var partBuffer [4]namePart
	parts := partBuffer[:0]
	prefixWireLength := 0
	off := start
	var tail nameSuffix
	terminalSize := 0

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

	var text [maxNamePresentationSize]byte
	rendered := text[:0]
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

func appendEscapedLabel(text, label []byte) []byte {
	for _, value := range label {
		switch value {
		case '.', ' ', '\'', '@', ';', '(', ')', '"', '\\':
			return appendEscapedLabelSlow(text, label)
		default:
			if value < ' ' || value > '~' {
				return appendEscapedLabelSlow(text, label)
			}
		}
	}
	return append(text, label...)
}

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

func malformed(off int, reason string) error {
	return fmt.Errorf("%w at offset %d: %s", ErrMalformed, off, reason)
}

func unsupportedLabel(off int, labelType byte) error {
	return fmt.Errorf("%w 0x%02x at offset %d", ErrUnsupportedLabel, labelType, off)
}
