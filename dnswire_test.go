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

	got, err := parse(data)
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
	var gotQuestions []Question
	for question := range got.Questions {
		gotQuestions = append(gotQuestions, question)
	}
	if !reflect.DeepEqual(gotQuestions, wantQuestions) {
		t.Fatalf("Questions = %#v, want %#v", gotQuestions, wantQuestions)
	}
	if got.Length != len(data) {
		t.Fatalf("Length = %d, want %d", got.Length, len(data))
	}
	seen := 0
	for range got.Questions {
		seen++
		if seen == 2 {
			break
		}
	}
	if seen != 2 {
		t.Fatalf("early iteration yielded %d questions, want 2", seen)
	}
}

func TestHeaderFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags uint16
		check func(Header) bool
	}{
		{"Response", 1 << 15, Header.Response},
		{"Authoritative", 1 << 10, Header.Authoritative},
		{"Truncated", 1 << 9, Header.Truncated},
		{"RecursionDesired", 1 << 8, Header.RecursionDesired},
		{"RecursionAvailable", 1 << 7, Header.RecursionAvailable},
		{"Zero", 1 << 6, Header.Zero},
		{"AuthenticatedData", 1 << 5, Header.AuthenticatedData},
		{"CheckingDisabled", 1 << 4, Header.CheckingDisabled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !test.check(Header{Flags: test.flags}) {
				t.Errorf("%s(%#04x) = false, want true", test.name, test.flags)
			}
			if test.check(Header{Flags: ^test.flags}) {
				t.Errorf("%s(%#04x) = true, want false", test.name, ^test.flags)
			}
		})
	}
}

func TestHeaderOpcodeRcode(t *testing.T) {
	tests := []struct {
		flags  uint16
		opcode int
		rcode  int
	}{
		{0, 0, 0},
		{0xffff, 15, 15},
		{5<<11 | 3, 5, 3},
		{1<<15 | 4<<11 | 1<<8 | 9, 4, 9},
	}
	for _, test := range tests {
		header := Header{Flags: test.flags}
		if got := header.Opcode(); got != test.opcode {
			t.Errorf("Opcode(%#04x) = %d, want %d", test.flags, got, test.opcode)
		}
		if got := header.Rcode(); got != test.rcode {
			t.Errorf("Rcode(%#04x) = %d, want %d", test.flags, got, test.rcode)
		}
	}
}

func TestParseNoQuestions(t *testing.T) {
	got, err := parse(testHeader(123, 0, 0, 0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got.Question != (Question{}) {
		t.Fatalf("Question = %#v, want zero value", got.Question)
	}
	if got.Length != HeaderSize {
		t.Fatalf("Length = %d, want %d", got.Length, HeaderSize)
	}
	for range got.Questions {
		t.Fatal("message yielded a question")
	}
}

func TestUnpackOverwritesMessage(t *testing.T) {
	var message Message
	multi := compressedQuestionPair(wireName([]byte("example"), []byte("com")))
	if err := message.Unpack(multi); err != nil {
		t.Fatal(err)
	}
	if err := message.Unpack(questionPacket(wireName([]byte("only")))); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for question := range message.Questions {
		if question.Name != "only." {
			t.Fatalf("Questions[%d].Name = %q, want %q", seen, question.Name, "only.")
		}
		seen++
	}
	if seen != 1 {
		t.Fatalf("decoded %d questions, want 1", seen)
	}
	if err := message.Unpack(testHeader(7, 0, 0, 0, 0, 0)); err != nil {
		t.Fatal(err)
	}
	want := Message{Header: Header{ID: 7}, Length: HeaderSize}
	if !reflect.DeepEqual(message, want) {
		t.Fatalf("Message = %#v, want %#v", message, want)
	}
}

func TestParseLengthIgnoresTrailingData(t *testing.T) {
	data := questionPacket(wireName([]byte("example"), []byte("com")))
	want := len(data)
	data = append(data, 0xde, 0xad, 0xbe, 0xef)
	got, err := parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Length != want {
		t.Fatalf("Length = %d, want %d", got.Length, want)
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
		{
			name: "maximum escaped name",
			labels: [][]byte{
				bytes.Repeat([]byte{0}, 63),
				bytes.Repeat([]byte{0}, 63),
				bytes.Repeat([]byte{0}, 63),
				bytes.Repeat([]byte{0}, 61),
			},
			want: strings.Repeat(`\000`, 63) + "." +
				strings.Repeat(`\000`, 63) + "." +
				strings.Repeat(`\000`, 63) + "." +
				strings.Repeat(`\000`, 61) + ".",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := testHeader(0, 0, 1, 0, 0, 0)
			data = append(data, wireName(test.labels...)...)
			data = appendUint16(data, 1)
			data = appendUint16(data, 1)

			got, err := parse(data)
			if err != nil {
				t.Fatal(err)
			}
			if got.Question.Name != test.want {
				t.Fatalf("Name = %q, want %q", got.Question.Name, test.want)
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

	got, err := parse(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com.", "example.com.", "example.com.", "."}
	i := 0
	for question := range got.Questions {
		if question.Name != want[i] {
			t.Errorf("Questions[%d].Name = %q, want %q", i, question.Name, want[i])
		}
		i++
	}
	if i != len(want) {
		t.Fatalf("decoded %d questions, want %d", i, len(want))
	}
}

func TestParseManyLabels(t *testing.T) {
	name := wireName([]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e"))
	got, err := parse(compressedQuestionPair(name))
	if err != nil {
		t.Fatal(err)
	}
	i := 0
	for question := range got.Questions {
		if question.Name != "a.b.c.d.e." {
			t.Errorf("Questions[%d].Name = %q, want %q", i, question.Name, "a.b.c.d.e.")
		}
		i++
	}
	if i != 2 {
		t.Fatalf("decoded %d questions, want 2", i)
	}
}

func TestParseHistoricBitStringLabel(t *testing.T) {
	data := testHeader(0, 0, 1, 0, 0, 0)
	data = append(data, 0x41, 14, 0xd0, 0x74, 0)
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)

	got, err := parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Question.Name != `\[xd074/14].` {
		t.Fatalf("Name = %q", got.Question.Name)
	}

	data = testHeader(0, 0, 1, 0, 0, 0)
	data = append(data, 0x41, 0)
	data = append(data, make([]byte, 32)...)
	data = append(data, 0)
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)
	got, err = parse(data)
	if err != nil {
		t.Fatal(err)
	}
	want := `\[x` + strings.Repeat("0", 64) + `/256].`
	if got.Question.Name != want {
		t.Fatalf("Name = %q, want %q", got.Question.Name, want)
	}

	// RFC 2673 requires receivers to ignore padding bits.
	data = questionPacket([]byte{0x41, 1, 0xff, 0})
	got, err = parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Question.Name != `\[x8/1].` {
		t.Fatalf("Name = %q", got.Question.Name)
	}

	data = questionPacket([]byte{0x41, 1, 0xff, 3, 'c', 'o', 'm', 0})
	got, err = parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Question.Name != `\[x8/1].com.` {
		t.Fatalf("Name = %q", got.Question.Name)
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
	if _, err := parse(data); err != nil {
		t.Fatalf("255-octet name: %v", err)
	}

	labels[3] = append(labels[3], 'd')
	if _, err := parse(questionPacket(wireName(labels...))); !errors.Is(err, ErrMalformed) {
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
			got, err := parse(test.data)
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

	got, err := parse(data)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed", err)
	}
	if !reflect.DeepEqual(got, Message{}) {
		t.Fatalf("Message = %#v, want zero value", got)
	}
}

// TestParseCompressedNameMaxLength exercises both sides of the 255-octet
// expanded-name limit for compressed names.
func TestParseCompressedNameMaxLength(t *testing.T) {
	// A 253-octet tail leaves room for exactly one 2-octet prefix label.
	tailLabels := [][]byte{
		bytes.Repeat([]byte{'a'}, 63),
		bytes.Repeat([]byte{'b'}, 63),
		bytes.Repeat([]byte{'c'}, 63),
		bytes.Repeat([]byte{'d'}, 59),
	}
	tail := wireName(tailLabels...)

	data := testHeader(0, 0, 2, 0, 0, 0)
	tailOffset := len(data)
	data = append(data, tail...)
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)
	data = append(data, 1, 'x', 0xc0, byte(tailOffset))
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)

	got, err := parse(data)
	if err != nil {
		t.Fatalf("255-octet compressed name: %v", err)
	}
	tailName := testPresentationName(tailLabels...)
	if got.Question.Name != tailName {
		t.Fatalf("Questions[0].Name = %q, want %q", got.Question.Name, tailName)
	}
	var last string
	for question := range got.Questions {
		last = question.Name
	}
	if want := "x." + tailName; last != want {
		t.Fatalf("Name = %q, want %q", last, want)
	}

	data = testHeader(0, 0, 2, 0, 0, 0)
	data = append(data, tail...)
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)
	data = append(data, 2, 'x', 'y', 0xc0, byte(tailOffset))
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)
	if _, err = parse(data); !errors.Is(err, ErrMalformed) {
		t.Fatalf("256-octet compressed name error = %v, want ErrMalformed", err)
	}
}

// TestParsePointerToBitStringBoundary verifies that compression pointers may
// target bit-string label boundaries of a prior name.
func TestParsePointerToBitStringBoundary(t *testing.T) {
	data := testHeader(0, 0, 3, 0, 0, 0)
	bitString := len(data)
	data = append(data, 0x41, 14, 0xd0, 0x74)
	com := len(data)
	data = append(data, 3, 'c', 'o', 'm', 0)
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)
	data = append(data, 0xc0, byte(bitString))
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)
	data = append(data, 0xc0, byte(com))
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)

	got, err := parse(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`\[xd074/14].com.`, `\[xd074/14].com.`, "com."}
	i := 0
	for question := range got.Questions {
		if question.Name != want[i] {
			t.Errorf("Questions[%d].Name = %q, want %q", i, question.Name, want[i])
		}
		i++
	}
	if i != len(want) {
		t.Fatalf("decoded %d questions, want %d", i, len(want))
	}
}

// TestParsePointerToLabelInterior verifies that a compression pointer into
// the interior of a decoded label is rejected.
func TestParsePointerToLabelInterior(t *testing.T) {
	data := testHeader(0, 0, 2, 0, 0, 0)
	firstName := len(data)
	data = append(data, wireName([]byte("example"), []byte("com"))...)
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)
	data = append(data, 0xc0, byte(firstName+1))
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)

	got, err := parse(data)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed", err)
	}
	if !reflect.DeepEqual(got, Message{}) {
		t.Fatalf("Message = %#v, want zero value", got)
	}
}

// TestParsePointerWithinOwnName verifies that a pointer to an earlier label
// of the name still being decoded is rejected: it would loop, and that label
// is not a completed boundary.
func TestParsePointerWithinOwnName(t *testing.T) {
	data := testHeader(0, 0, 1, 0, 0, 0)
	nameStart := len(data)
	data = append(data, 1, 'a', 1, 'b', 0xc0, byte(nameStart+2))
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)

	got, err := parse(data)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed", err)
	}
	if !reflect.DeepEqual(got, Message{}) {
		t.Fatalf("Message = %#v, want zero value", got)
	}
}

// TestParseMaxQuestionCount parses the largest question count that can fit
// in a maximum-size message and rejects a count of one more.
func TestParseMaxQuestionCount(t *testing.T) {
	const count = (maxMessageSize - HeaderSize) / 5
	data := testHeader(0, 0, count, 0, 0, 0)
	for range count {
		data = append(data, 0)
		data = appendUint16(data, 1)
		data = appendUint16(data, 1)
	}

	got, err := parse(data)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for question := range got.Questions {
		if question.Name != "." {
			t.Fatalf("Questions[%d].Name = %q, want %q", seen, question.Name, ".")
		}
		seen++
	}
	if seen != count {
		t.Fatalf("decoded %d questions, want %d", seen, count)
	}

	binary.BigEndian.PutUint16(data[4:6], count+1)
	if _, err = parse(data); !errors.Is(err, ErrMalformed) {
		t.Fatalf("question count %d error = %v, want ErrMalformed", count+1, err)
	}
}

// TestParseWorstCaseCompressionAmplification fills a maximum-size message
// with escape-heavy compressed names: each 8-octet question decodes to a name
// near the 1020-octet presentation limit. Parse must stay linear and every
// name must decode correctly.
func TestParseWorstCaseCompressionAmplification(t *testing.T) {
	tailLabels := [][]byte{
		bytes.Repeat([]byte{0}, 63),
		bytes.Repeat([]byte{0}, 63),
		bytes.Repeat([]byte{0}, 63),
		bytes.Repeat([]byte{0}, 59),
	}
	data := testHeader(0, 0, 0, 0, 0, 0)
	tailOffset := len(data)
	data = append(data, wireName(tailLabels...)...)
	data = appendUint16(data, 1)
	data = appendUint16(data, 1)

	tailName := testPresentationName(tailLabels...)
	wantName := `\000.` + tailName
	questions := 1
	for len(data)+8 <= maxMessageSize {
		data = append(data, 1, 0, 0xc0, byte(tailOffset))
		data = appendUint16(data, 1)
		data = appendUint16(data, 1)
		questions++
	}
	binary.BigEndian.PutUint16(data[4:6], uint16(questions))

	got, err := parse(data)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for question := range got.Questions {
		want := wantName
		if seen == 0 {
			want = tailName
		}
		if question.Name != want {
			t.Fatalf("Questions[%d].Name = %q, want %q", seen, question.Name, want)
		}
		if len(question.Name) > maxNamePresentationSize {
			t.Fatalf("Questions[%d].Name is %d octets, exceeding %d", seen, len(question.Name), maxNamePresentationSize)
		}
		seen++
	}
	if seen != questions {
		t.Fatalf("decoded %d questions, want %d", seen, questions)
	}
}

// FuzzParse checks Parse's invariants on arbitrary input: stable error
// identities, a zero Message on error, input immutability, absolute names
// within the presentation-size bound, question-count agreement with the
// header, and determinism.
func FuzzParse(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(questionPacket(wireName([]byte("example"), []byte("com"))))
	f.Add(questionPacket(wireName([]byte("a.b"), []byte{0, 255})))
	f.Add(questionPacket([]byte{0x41, 14, 0xd0, 0x74, 0}))
	f.Add(questionPacket([]byte{0xc0, 0x0c}))
	f.Add(compressedQuestionPair([]byte{0x41, 14, 0xd0, 0x74, 3, 'c', 'o', 'm', 0}))
	f.Add(append(testHeader(0, 0, 1, 0, 0, 0), 1, 'a', 1, 'b', 0xc0, HeaderSize+2, 0, 1, 0, 1))

	f.Fuzz(func(t *testing.T, data []byte) {
		before := bytes.Clone(data)
		got, err := parse(data)
		if !bytes.Equal(data, before) {
			t.Fatal("Parse modified its input")
		}
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrUnsupportedLabel) {
				t.Fatalf("unexpected error identity: %v", err)
			}
			if !reflect.DeepEqual(got, Message{}) {
				t.Fatalf("Message = %#v, want zero value on error", got)
			}
			return
		}
		questionCount := 0
		for question := range got.Questions {
			questionCount++
			if !strings.HasSuffix(question.Name, ".") {
				t.Fatalf("non-absolute decoded name %q", question.Name)
			}
			if len(question.Name) > maxNamePresentationSize {
				t.Fatalf("decoded name is %d octets, exceeding %d", len(question.Name), maxNamePresentationSize)
			}
		}
		if questionCount != int(got.Header.QuestionCount) {
			t.Fatalf("decoded %d questions, header says %d", questionCount, got.Header.QuestionCount)
		}
		if got.Length < HeaderSize || got.Length > len(data) {
			t.Fatalf("Length = %d, data is %d octets", got.Length, len(data))
		}
		prefix, err := parse(data[:got.Length])
		if err != nil || !reflect.DeepEqual(got, prefix) {
			t.Fatalf("Unpack of %d-octet prefix = (%#v, %v), want (%#v, nil)", got.Length, prefix, err, got)
		}
		again, err := parse(data)
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
			got, err := parse(data)
			if err != nil {
				t.Fatal(err)
			}
			i := 0
			for question := range got.Questions {
				if question.Name != want {
					t.Fatalf("Questions[%d].Name = %q, want %q", i, question.Name, want)
				}
				i++
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

		got, err := parse(compressedQuestionPair(name))
		if err != nil {
			t.Fatal(err)
		}
		want := testBitStringPresentation(payload, bits)
		i := 0
		for question := range got.Questions {
			if question.Name != want {
				t.Fatalf("Questions[%d].Name = %q, want %q", i, question.Name, want)
			}
			i++
		}
	})
}

// parse unpacks data into a fresh Message.
func parse(data []byte) (message Message, err error) {
	err = message.Unpack(data)
	return
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
