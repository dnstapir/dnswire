// Package dnswire parses DNS headers and question sections.
package dnswire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// HeaderSize is the size of a DNS message header in octets.
const HeaderSize = 12

const (
	maxMessageSize  = 1<<16 - 1
	maxNameWireSize = 255
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
	Header    Header
	Questions []Question
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

	questionCount := int(message.Header.QuestionCount)
	if questionCount > (len(data)-HeaderSize)/5 {
		message = Message{}
		err = malformed(HeaderSize, "question count cannot fit in message")
		return
	}

	message.Questions = make([]Question, 0, questionCount)
	names := make(map[int]nameSuffix)
	off := HeaderSize
	for i := 0; i < questionCount; i++ {
		var question Question
		question.Name, off, err = unpackName(data, off, names)
		if err == nil && off+4 > len(data) {
			err = malformed(off, "question type or class is truncated")
		}
		if err == nil {
			question.Type = binary.BigEndian.Uint16(data[off : off+2])
			question.Class = binary.BigEndian.Uint16(data[off+2 : off+4])
			off += 4
			message.Questions = append(message.Questions, question)
			continue
		}

		message = Message{}
		err = fmt.Errorf("question %d: %w", i, err)
		return
	}
	return
}

type namePart struct {
	offset     int
	text       string
	wireLength int
}

type nameSuffix struct {
	text       string
	wireLength int
}

func unpackName(data []byte, start int, names map[int]nameSuffix) (name string, next int, err error) {
	parts := make([]namePart, 0, 4)
	prefixWireLength := 0
	off := start

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
				tail := nameSuffix{wireLength: 1}
				names[labelOffset] = tail
				var result nameSuffix
				result, err = completeName(parts, tail, names)
				if err == nil {
					name = presentationName(result)
					next = off + 1
				}
				return
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
				text:       escapeLabel(data[off+1 : end]),
				wireLength: 1 + labelLength,
			})
			off = end

		case 0x40:
			if length != 0x41 {
				err = unsupportedLabel(off, length)
				return
			}
			var part namePart
			part.offset = labelOffset
			part.text, part.wireLength, off, err = unpackBitStringLabel(data, off)
			if err != nil {
				return
			}
			prefixWireLength += part.wireLength
			if prefixWireLength >= maxNameWireSize {
				err = malformed(start, "domain name exceeds 255 octets")
				return
			}
			parts = append(parts, part)

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
			tail, ok := names[target]
			if !ok {
				err = malformed(off, "compression pointer target is not a prior label boundary")
				return
			}
			names[labelOffset] = tail
			var result nameSuffix
			result, err = completeName(parts, tail, names)
			if err == nil {
				name = presentationName(result)
				next = off + 2
			}
			return

		default:
			err = malformed(off, "unallocated DNS label type")
			return
		}
	}
}

func completeName(parts []namePart, tail nameSuffix, names map[int]nameSuffix) (result nameSuffix, err error) {
	result = tail
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if part.wireLength > maxNameWireSize-result.wireLength {
			err = malformed(part.offset, "domain name exceeds 255 octets")
			return
		}
		result.wireLength += part.wireLength
		if result.text == "" {
			result.text = part.text + "."
		} else {
			result.text = part.text + "." + result.text
		}
		names[part.offset] = result
	}
	return
}

func presentationName(name nameSuffix) string {
	if name.text == "" {
		return "."
	}
	return name.text
}

func unpackBitStringLabel(data []byte, off int) (text string, wireLength int, next int, err error) {
	if off+1 >= len(data) {
		err = malformed(off, "bit-string label has no bit count")
		return
	}
	bits := int(data[off+1])
	if bits == 0 {
		bits = 256
	}
	byteCount := (bits + 7) / 8
	next = off + 2 + byteCount
	if next > len(data) {
		err = malformed(off, "bit-string label is truncated")
		return
	}

	text = bitStringPresentation(data[off+2:next], bits)
	wireLength = 2 + byteCount
	return
}

func bitStringPresentation(data []byte, bits int) string {
	const hexDigits = "0123456789abcdef"
	digitCount := (bits + 3) / 4

	var text strings.Builder
	text.Grow(digitCount + 8)
	text.WriteString(`\[x`)
	for i := 0; i < digitCount; i++ {
		value := data[i/2]
		if i%2 == 0 {
			value >>= 4
		} else {
			value &= 0x0f
		}
		if i == digitCount-1 && bits%4 != 0 {
			value &= 0x0f << (4 - bits%4)
		}
		text.WriteByte(hexDigits[value])
	}
	text.WriteByte('/')
	text.WriteString(strconv.Itoa(bits))
	text.WriteByte(']')
	return text.String()
}

func escapeLabel(label []byte) string {
	var text strings.Builder
	text.Grow(len(label))
	for _, value := range label {
		switch value {
		case '.', ' ', '\'', '@', ';', '(', ')', '"', '\\':
			text.WriteByte('\\')
			text.WriteByte(value)
		default:
			if value < ' ' || value > '~' {
				text.WriteByte('\\')
				text.WriteByte('0' + value/100)
				text.WriteByte('0' + value/10%10)
				text.WriteByte('0' + value%10)
			} else {
				text.WriteByte(value)
			}
		}
	}
	return text.String()
}

func malformed(off int, reason string) error {
	return fmt.Errorf("%w at offset %d: %s", ErrMalformed, off, reason)
}

func unsupportedLabel(off int, labelType byte) error {
	return fmt.Errorf("%w 0x%02x at offset %d", ErrUnsupportedLabel, labelType, off)
}
