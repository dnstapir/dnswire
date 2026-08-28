package dnswire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestParseHeaderAndQuestions(t *testing.T) {
	data := testHeader(0x1234, 0x85a3, 2, 7, 8, 9)
	firstName := len(data)
	data = append(data, wireName([]byte("example"), []byte("com"))...)
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)

	data = append(data, 3, 'w', 'w', 'w', 0xc0, byte(firstName+8))
	data = appendUint16(data, 28)
	data = appendUint16(data, 255)

	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	wantHeader := Header{
		ID:              0x1234,
		Flags:           0x85a3,
		QuestionCount:   2,
		AnswerCount:     7,
		AuthorityCount:  8,
		AdditionalCount: 9,
	}
	if got.Header != wantHeader {
		t.Fatalf("Header = %#v, want %#v", got.Header, wantHeader)
	}
	wantQuestions := []Question{
		{Name: "example.com.", Type: 1, Class: 1},
		{Name: "www.com.", Type: 28, Class: 255},
	}
	if !reflect.DeepEqual(got.Questions, wantQuestions) {
		t.Fatalf("Questions = %#v, want %#v", got.Questions, wantQuestions)
	}
}

func TestParsePresentationNames(t *testing.T) {
	tests := []struct {
		name   string
		labels [][]byte
		want   string
	}{
		{name: "root", want: "."},
		{name: "embedded dot", labels: [][]byte{[]byte("a.b"), []byte("example")}, want: `a\.b.example.`},
		{name: "backslash", labels: [][]byte{[]byte(`a\b`), []byte("example")}, want: `a\\b.example.`},
		{name: "special ASCII", labels: [][]byte{[]byte("a b'@;()\"")}, want: `a\ b\'\@\;\(\)\".`},
		{name: "control octets", labels: [][]byte{{0, 7, 9, 10, 31}}, want: `\000\007\009\010\031.`},
		{name: "high octets", labels: [][]byte{{127, 128, 173, 239, 255}, []byte("example")}, want: `\127\128\173\239\255.example.`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := testHeader(0, 0, 1, 0, 0, 0)
			data = append(data, wireName(test.labels...)...)
			data = appendUint16(data, 1)
			data = appendUint16(data, 1)

			got, err := Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			if got.Questions[0].Name != test.want {
				t.Fatalf("Name = %q, want %q", got.Questions[0].Name, test.want)
			}
		})
	}
}

func TestParseCompressionPointerChain(t *testing.T) {
	data := testHeader(0, 0, 4, 0, 0, 0)
	firstName := len(data)
	data = append(data, wireName([]byte("example"), []byte("com"))...)
	root := len(data) - 1
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)

	secondName := len(data)
	data = append(data, 0xc0, byte(firstName))
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)

	data = append(data, 0xc0, byte(secondName))
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)

	data = append(data, 0xc0, byte(root))
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)

	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com.", "example.com.", "example.com.", "."}
	for i, question := range got.Questions {
		if question.Name != want[i] {
			t.Errorf("Questions[%d].Name = %q, want %q", i, question.Name, want[i])
		}
	}
}

func TestParseManyLabels(t *testing.T) {
	name := wireName([]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e"))
	got, err := Parse(compressedQuestionPair(name))
	if err != nil {
		t.Fatal(err)
	}
	for i, question := range got.Questions {
		if question.Name != "a.b.c.d.e." {
			t.Errorf("Questions[%d].Name = %q, want %q", i, question.Name, "a.b.c.d.e.")
		}
	}
}

func TestParseHistoricBitStringLabel(t *testing.T) {
	data := testHeader(0, 0, 1, 0, 0, 0)
	data = append(data, 0x41, 14, 0xd0, 0x74, 0)
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)

	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Questions[0].Name != `\[xd074/14].` {
		t.Fatalf("Name = %q", got.Questions[0].Name)
	}

	data = testHeader(0, 0, 1, 0, 0, 0)
	data = append(data, 0x41, 0)
	data = append(data, make([]byte, 32)...)
	data = append(data, 0)
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)
	got, err = Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	want := `\[x` + strings.Repeat("0", 64) + `/256].`
	if got.Questions[0].Name != want {
		t.Fatalf("Name = %q, want %q", got.Questions[0].Name, want)
	}

	// RFC 2673 requires receivers to ignore padding bits.
	data = questionPacket([]byte{0x41, 1, 0xff, 0})
	got, err = Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Questions[0].Name != `\[x8/1].` {
		t.Fatalf("Name = %q", got.Questions[0].Name)
	}

	data = questionPacket([]byte{0x41, 1, 0xff, 3, 'c', 'o', 'm', 0})
	got, err = Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Questions[0].Name != `\[x8/1].com.` {
		t.Fatalf("Name = %q", got.Questions[0].Name)
	}
}

func TestParseNameWireLengthLimit(t *testing.T) {
	labels := [][]byte{
		bytes.Repeat([]byte{'a'}, 63),
		bytes.Repeat([]byte{'b'}, 63),
		bytes.Repeat([]byte{'c'}, 63),
		bytes.Repeat([]byte{'d'}, 61),
	}
	data := questionPacket(wireName(labels...))
	if _, err := Parse(data); err != nil {
		t.Fatalf("255-octet name: %v", err)
	}

	labels[3] = append(labels[3], 'd')
	if _, err := Parse(questionPacket(wireName(labels...))); !errors.Is(err, ErrMalformed) {
		t.Fatalf("256-octet name error = %v, want ErrMalformed", err)
	}
}

func TestParseMalformed(t *testing.T) {
	tooLarge := make([]byte, maxMessageSize+1)
	genericUnterminated := append(testHeader(0, 0, 2, 0, 0, 0), 9, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a')
	genericTruncated := append(testHeader(0, 0, 2, 0, 0, 0), 10, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a')
	genericTooLong := append(testHeader(0, 0, 2, 0, 0, 0), wireName(
		bytes.Repeat([]byte{'a'}, 63),
		bytes.Repeat([]byte{'b'}, 63),
		bytes.Repeat([]byte{'c'}, 63),
		bytes.Repeat([]byte{'d'}, 62),
	)...)
	tooManyBitStrings := make([]byte, 0, 8*34)
	for range 8 {
		tooManyBitStrings = append(tooManyBitStrings, 0x41, 0)
		tooManyBitStrings = append(tooManyBitStrings, make([]byte, 32)...)
	}

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{name: "short header", data: make([]byte, HeaderSize-1), want: ErrMalformed},
		{name: "oversized message", data: tooLarge, want: ErrMalformed},
		{name: "impossible question count", data: testHeader(0, 0, 1, 0, 0, 0), want: ErrMalformed},
		{name: "unterminated name", data: append(testHeader(0, 0, 1, 0, 0, 0), 4, 'a', 'b', 'c', 'd'), want: ErrMalformed},
		{name: "truncated label", data: append(testHeader(0, 0, 1, 0, 0, 0), 5, 'a', 'b', 'c', 'd'), want: ErrMalformed},
		{name: "generic unterminated name", data: genericUnterminated, want: ErrMalformed},
		{name: "generic truncated label", data: genericTruncated, want: ErrMalformed},
		{name: "generic name too long", data: genericTooLong, want: ErrMalformed},
		{name: "truncated type and class", data: append(testHeader(0, 0, 1, 0, 0, 0), 1, 'a', 0, 0, 1), want: ErrMalformed},
		{name: "truncated pointer", data: append(testHeader(0, 0, 1, 0, 0, 0), 3, 'a', 'b', 'c', 0xc0), want: ErrMalformed},
		{name: "forward pointer", data: questionPacket([]byte{0xc0, HeaderSize + 2}), want: ErrMalformed},
		{name: "unknown pointer target", data: questionPacket([]byte{0xc0, 0}), want: ErrMalformed},
		{name: "unknown extended label", data: questionPacket([]byte{0x42}), want: ErrUnsupportedLabel},
		{name: "unallocated label type", data: questionPacket([]byte{0x80}), want: ErrMalformed},
		{name: "bit-string count missing", data: append(testHeader(0, 0, 1, 0, 0, 0), 3, 'a', 'b', 'c', 0x41), want: ErrMalformed},
		{name: "bit-string data truncated", data: append(testHeader(0, 0, 1, 0, 0, 0), 0x41, 32, 0, 0, 0), want: ErrMalformed},
		{name: "bit-string name too long", data: questionPacket(tooManyBitStrings), want: ErrMalformed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Parse(test.data)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if !reflect.DeepEqual(got, Message{}) {
				t.Fatalf("Message = %#v, want zero value", got)
			}
		})
	}
}

func TestParseCompressedNameTooLong(t *testing.T) {
	labels := [][]byte{
		bytes.Repeat([]byte{'a'}, 63),
		bytes.Repeat([]byte{'b'}, 63),
		bytes.Repeat([]byte{'c'}, 63),
		bytes.Repeat([]byte{'d'}, 60),
	}
	data := testHeader(0, 0, 2, 0, 0, 0)
	firstName := len(data)
	data = append(data, wireName(labels...)...)
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)
	data = append(data, 1, 'x', 0xc0, byte(firstName))
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)

	got, err := Parse(data)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed", err)
	}
	if !reflect.DeepEqual(got, Message{}) {
		t.Fatalf("Message = %#v, want zero value", got)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(questionPacket(wireName([]byte("example"), []byte("com"))))
	f.Add(questionPacket(wireName([]byte("a.b"), []byte{0, 255})))
	f.Add(questionPacket([]byte{0x41, 14, 0xd0, 0x74, 0}))
	f.Add(questionPacket([]byte{0xc0, 0x0c}))

	f.Fuzz(func(t *testing.T, data []byte) {
		before := bytes.Clone(data)
		got, err := Parse(data)
		if !bytes.Equal(data, before) {
			t.Fatal("Parse modified its input")
		}
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrUnsupportedLabel) {
				t.Fatalf("unexpected error identity: %v", err)
			}
			return
		}
		if len(got.Questions) != int(got.Header.QuestionCount) {
			t.Fatalf("decoded %d questions, header says %d", len(got.Questions), got.Header.QuestionCount)
		}
		for _, question := range got.Questions {
			if !strings.HasSuffix(question.Name, ".") {
				t.Fatalf("non-absolute decoded name %q", question.Name)
			}
		}
		again, err := Parse(data)
		if err != nil || !reflect.DeepEqual(got, again) {
			t.Fatalf("second Parse = (%#v, %v), want (%#v, nil)", again, err, got)
		}
	})
}

func FuzzParseOrdinaryName(f *testing.F) {
	f.Add([]byte("example"), []byte("com"))
	f.Add([]byte("a.b"), []byte(`a\b`))
	f.Add([]byte{0, 7, 31}, []byte{127, 128, 255})
	f.Add([]byte(nil), []byte(nil))

	f.Fuzz(func(t *testing.T, first, second []byte) {
		if len(first) > 63 || len(second) > 63 {
			t.Skip()
		}
		labels := make([][]byte, 0, 2)
		if len(first) != 0 {
			labels = append(labels, first)
		}
		if len(second) != 0 {
			labels = append(labels, second)
		}

		name := wireName(labels...)
		want := testPresentationName(labels...)
		for _, data := range [][]byte{questionPacket(name), compressedQuestionPair(name)} {
			got, err := Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			for i, question := range got.Questions {
				if question.Name != want {
					t.Fatalf("Questions[%d].Name = %q, want %q", i, question.Name, want)
				}
			}
		}
	})
}

func FuzzParseHistoricBitString(f *testing.F) {
	f.Add(uint8(14), []byte{0xd0, 0x74})
	f.Add(uint8(1), []byte{0xff})
	f.Add(uint8(0), make([]byte, 32))

	f.Fuzz(func(t *testing.T, count uint8, input []byte) {
		bits := int(count)
		if bits == 0 {
			bits = 256
		}
		payload := make([]byte, (bits+7)/8)
		copy(payload, input)
		name := append([]byte{0x41, count}, payload...)
		name = append(name, 0)

		got, err := Parse(compressedQuestionPair(name))
		if err != nil {
			t.Fatal(err)
		}
		want := testBitStringPresentation(payload, bits)
		for i, question := range got.Questions {
			if question.Name != want {
				t.Fatalf("Questions[%d].Name = %q, want %q", i, question.Name, want)
			}
		}
	})
}

func testHeader(id, flags, questions, answers, authorities, additionals uint16) []byte {
	data := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(data[0:2], id)
	binary.BigEndian.PutUint16(data[2:4], flags)
	binary.BigEndian.PutUint16(data[4:6], questions)
	binary.BigEndian.PutUint16(data[6:8], answers)
	binary.BigEndian.PutUint16(data[8:10], authorities)
	binary.BigEndian.PutUint16(data[10:12], additionals)
	return data
}

func questionPacket(name []byte) []byte {
	data := testHeader(0, 0, 1, 0, 0, 0)
	data = append(data, name...)
	data = appendUint16(data, 1)
	return appendUint16(data, 1)
}

func compressedQuestionPair(name []byte) []byte {
	data := testHeader(0, 0, 2, 0, 0, 0)
	data = append(data, name...)
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)
	data = append(data, 0xc0, HeaderSize)
	data = appendUint16(data, 1)
	return appendUint16(data, 1)
}

func wireName(labels ...[]byte) []byte {
	var data []byte
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			panic("invalid test label length")
		}
		data = append(data, byte(len(label)))
		data = append(data, label...)
	}
	return append(data, 0)
}

func appendUint16(data []byte, value uint16) []byte {
	return binary.BigEndian.AppendUint16(data, value)
}

func testPresentationName(labels ...[]byte) string {
	if len(labels) == 0 {
		return "."
	}
	var name strings.Builder
	for _, label := range labels {
		for _, value := range label {
			switch value {
			case '.', ' ', '\'', '@', ';', '(', ')', '"', '\\':
				name.WriteByte('\\')
				name.WriteByte(value)
			default:
				if value < ' ' || value > '~' {
					name.WriteByte('\\')
					name.WriteByte('0' + value/100)
					name.WriteByte('0' + value/10%10)
					name.WriteByte('0' + value%10)
				} else {
					name.WriteByte(value)
				}
			}
		}
		name.WriteByte('.')
	}
	return name.String()
}

func testBitStringPresentation(data []byte, bits int) string {
	canonical := bytes.Clone(data)
	if unusedBits := len(canonical)*8 - bits; unusedBits != 0 {
		canonical[len(canonical)-1] &= ^byte((1 << unusedBits) - 1)
	}
	digits := hex.EncodeToString(canonical)
	digits = digits[:(bits+3)/4]
	return `\[x` + digits + `/` + strconv.Itoa(bits) + `].`
}
