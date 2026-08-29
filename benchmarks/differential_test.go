package benchmarks_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"reflect"
	"testing"

	"github.com/dnstapir/dnswire"
	dnsv1 "github.com/miekg/dns"
)

// This file cross-checks dnswire.Message.Unpack against an independent legal-message
// oracle and against miekg/dns v1 question decoding. miekg/dns v2 is not
// compared: it intentionally does not decode legacy QNAMEs and its
// presentation names are lossy, so neither its accept/reject decisions nor
// its names are a usable reference.

// nameBoundary records a legal compression target: the wire offset of a name
// occurrence, the expanded wire length of the name starting there including
// the root octet, and its expected presentation text ("" for the root).
type nameBoundary struct {
	offset int
	wire   int
	text   string
}

// escapeOracle mirrors dnswire's documented RFC 1035 presentation escaping
// independently of the implementation under test.
func escapeOracle(label []byte) string {
	var text []byte
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
	return string(text)
}

// legalMessage builds a spec-legal header-and-question message: random binary
// labels within the 63-octet limit, expanded names within the 255-octet
// limit, and compression pointers only to prior name occurrences. It returns
// the message and the expected presentation name of every question.
func legalMessage(r *rand.Rand) (data []byte, want []string) {
	const maxNameWire = 255
	questions := r.IntN(5)
	data = make([]byte, dnswire.HeaderSize)
	binary.BigEndian.PutUint16(data[0:2], uint16(r.Uint32()))
	binary.BigEndian.PutUint16(data[2:4], uint16(r.Uint32()))
	binary.BigEndian.PutUint16(data[4:6], uint16(questions))
	var boundaries []nameBoundary

	for range questions {
		type prefixLabel struct {
			offset int
			text   string
			wire   int
		}
		var labels []prefixLabel
		prefixWire := 0
		tail := nameBoundary{wire: 1}
		pointer := false
		for {
			roll := r.IntN(100)
			if roll < 55 {
				// Leave room for the label length octet and the root octet.
				maxLength := min(63, maxNameWire-2-prefixWire)
				if maxLength < 1 {
					break
				}
				length := 1 + r.IntN(min(12, maxLength))
				if r.IntN(4) == 0 {
					length = 1 + r.IntN(maxLength)
				}
				label := make([]byte, length)
				for i := range label {
					if r.IntN(4) == 0 {
						label[i] = byte(r.Uint32())
					} else {
						label[i] = "abcdefghijklmnopqrstuvwxyz0123456789-"[r.IntN(37)]
					}
				}
				labels = append(labels, prefixLabel{offset: len(data), text: escapeOracle(label), wire: 1 + length})
				data = append(data, byte(length))
				data = append(data, label...)
				prefixWire += 1 + length
				continue
			}
			if roll < 85 {
				for tries := 0; tries < 8 && len(boundaries) > 0; tries++ {
					candidate := boundaries[r.IntN(len(boundaries))]
					if prefixWire+candidate.wire <= maxNameWire {
						tail = candidate
						pointer = true
						break
					}
				}
			}
			break
		}

		suffixText, suffixWire := tail.text, tail.wire
		for i := len(labels) - 1; i >= 0; i-- {
			suffixText = labels[i].text + "." + suffixText
			suffixWire += labels[i].wire
			boundaries = append(boundaries, nameBoundary{offset: labels[i].offset, wire: suffixWire, text: suffixText})
		}
		if pointer {
			boundaries = append(boundaries, nameBoundary{offset: len(data), wire: tail.wire, text: tail.text})
			data = append(data, 0xc0|byte(tail.offset>>8), byte(tail.offset))
		} else {
			boundaries = append(boundaries, nameBoundary{offset: len(data), wire: 1})
			data = append(data, 0)
		}
		name := suffixText
		if name == "" {
			name = "."
		}
		want = append(want, name)
		data = binary.BigEndian.AppendUint16(data, uint16(r.Uint32()))
		data = binary.BigEndian.AppendUint16(data, uint16(r.Uint32()))
	}
	return
}

// presentationLabels decodes a presentation name into raw label octets so
// names using different (but equally legal) escape sets compare equal.
func presentationLabels(name string) (labels [][]byte, ok bool) {
	if name == "." {
		return nil, true
	}
	current := []byte{}
	for i := 0; i < len(name); {
		switch c := name[i]; {
		case c == '\\':
			if i+1 >= len(name) {
				return
			}
			if d := name[i+1]; d >= '0' && d <= '9' {
				if i+3 >= len(name) {
					return
				}
				current = append(current, byte(int(d-'0')*100+int(name[i+2]-'0')*10+int(name[i+3]-'0')))
				i += 4
			} else {
				current = append(current, d)
				i += 2
			}
		case c == '.':
			labels = append(labels, current)
			current = []byte{}
			i++
		default:
			current = append(current, c)
			i++
		}
	}
	ok = len(current) == 0
	return
}

// compareHeader verifies that the Header flag accessors agree with the
// header fields miekg/dns v1 decoded. v1 folds EDNS0 extended RCODE bits
// into Rcode when an OPT record is present, so only its low four bits count.
func compareHeader(t *testing.T, data []byte, header dnswire.Header, v1 *dnsv1.Msg) {
	t.Helper()
	if header.ID != v1.Id || header.Response() != v1.Response || header.Opcode() != v1.Opcode ||
		header.Authoritative() != v1.Authoritative || header.Truncated() != v1.Truncated ||
		header.RecursionDesired() != v1.RecursionDesired || header.RecursionAvailable() != v1.RecursionAvailable ||
		header.Zero() != v1.Zero || header.AuthenticatedData() != v1.AuthenticatedData ||
		header.CheckingDisabled() != v1.CheckingDisabled || header.Rcode() != v1.Rcode&0xf {
		t.Fatalf("Unpack(%x) header = %+v, miekg/dns v1 = %+v", data, header, v1.MsgHdr)
	}
}

// compareQuestions verifies that dnswire and miekg/dns v1 decoded the same
// questions from data, comparing names by raw label octets.
func compareQuestions(t *testing.T, data []byte, message dnswire.Message, v1 *dnsv1.Msg) {
	t.Helper()
	compareHeader(t, data, message.Header, v1)
	i := 0
	for question := range message.Questions {
		if i >= len(v1.Question) {
			t.Fatalf("Unpack(%x) decoded more than the %d questions miekg/dns v1 decoded", data, len(v1.Question))
		}
		got, gotOK := presentationLabels(question.Name)
		want, wantOK := presentationLabels(v1.Question[i].Name)
		if !gotOK || !wantOK || !reflect.DeepEqual(got, want) {
			t.Fatalf("Unpack(%x) question %d name = %q, miekg/dns v1 = %q", data, i, question.Name, v1.Question[i].Name)
		}
		if question.Type != v1.Question[i].Qtype || question.Class != v1.Question[i].Qclass {
			t.Fatalf("Unpack(%x) question %d type/class = %d/%d, miekg/dns v1 = %d/%d",
				data, i, question.Type, question.Class, v1.Question[i].Qtype, v1.Question[i].Qclass)
		}
		i++
	}
	if i != len(v1.Question) {
		t.Fatalf("Unpack(%x) decoded %d questions, miekg/dns v1 decoded %d", data, i, len(v1.Question))
	}
}

// differential parses data with both implementations and compares the results
// where a comparison is meaningful. miekg/dns v1 accepts some spec-illegal
// messages (truncated question fields, pointers into bytes that are not a
// prior name occurrence) and rejects some legal ones (RFC 2673 binary
// labels), so acceptance itself is not compared; decoded questions are.
func differential(t *testing.T, data []byte) {
	t.Helper()
	var message dnswire.Message
	err := message.Unpack(data)
	if err != nil {
		if !errors.Is(err, dnswire.ErrMalformed) && !errors.Is(err, dnswire.ErrUnsupportedLabel) {
			t.Fatalf("Unpack(%x) unexpected error identity: %v", data, err)
		}
		if !reflect.DeepEqual(message, dnswire.Message{}) {
			t.Fatalf("Unpack(%x) = %#v, want zero Message on error", data, message)
		}
		return
	}
	var v1 dnsv1.Msg
	if v1.Unpack(data) == nil {
		compareQuestions(t, data, message, &v1)
	}
}

// TestParseLegalMessages verifies that Parse accepts every generated
// spec-legal message and decodes the names the oracle expects, cross-checked
// against miekg/dns v1 where it accepts the same message.
func TestParseLegalMessages(t *testing.T) {
	r := rand.New(rand.NewPCG(2026, 8))
	for range 100_000 {
		data, want := legalMessage(r)
		var message dnswire.Message
		err := message.Unpack(data)
		if err != nil {
			t.Fatalf("Unpack(%x) = %v, want success", data, err)
		}
		i := 0
		for question := range message.Questions {
			if i >= len(want) || question.Name != want[i] {
				t.Fatalf("Unpack(%x) question %d name = %q, oracle = %q", data, i, question.Name, want[i])
			}
			i++
		}
		if i != len(want) {
			t.Fatalf("Unpack(%x) decoded %d questions, oracle has %d", data, i, len(want))
		}
		var v1 dnsv1.Msg
		if v1.Unpack(data) == nil {
			compareQuestions(t, data, message, &v1)
		}
	}
}

// TestParseMutationDifferential runs the differential comparison on random
// mutations of legal messages, deterministically seeded.
func TestParseMutationDifferential(t *testing.T) {
	r := rand.New(rand.NewPCG(2026, 28))
	seeds := make([][]byte, 40)
	for i := range seeds {
		seeds[i], _ = legalMessage(r)
	}
	for range 100_000 {
		data := bytes.Clone(seeds[r.IntN(len(seeds))])
		for i := 1 + r.IntN(8); i > 0 && len(data) > 0; i-- {
			switch r.IntN(10) {
			case 0:
				data = data[:r.IntN(len(data)+1)]
			case 1:
				data = append(data, byte(r.Uint32()))
			default:
				data[r.IntN(len(data))] = byte(r.Uint32())
			}
		}
		differential(t, data)
	}
}

// FuzzParseDifferential fuzzes the differential comparison against miekg/dns
// v1 starting from generated legal messages.
func FuzzParseDifferential(f *testing.F) {
	r := rand.New(rand.NewPCG(20, 26))
	for range 8 {
		data, _ := legalMessage(r)
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		differential(t, data)
	})
}
