package dnswire_test

import (
	"encoding/binary"
	"testing"

	dnsv2 "codeberg.org/miekg/dns"
	"github.com/linkdata/dnswire"
	dnsv1 "github.com/miekg/dns"
)

var (
	resultName          string
	resultID            uint16
	resultType          uint16
	resultClass         uint16
	resultQuestionCount int
)

func BenchmarkParse(b *testing.B) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "typical", data: singleQuestion([][]byte{[]byte("www"), []byte("example"), []byte("com")})},
		{name: "unusual", data: singleQuestion([][]byte{{'a', '.', '\\', 0, 31, 127, 128, 255}, []byte("example")})},
		{name: "compressed", data: compressedQuestions()},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.Run("dnswire", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(test.data)))
				for b.Loop() {
					message, err := dnswire.Parse(test.data)
					if err != nil {
						b.Fatal(err)
					}
					question := message.Questions[0]
					resultName = question.Name
					resultID = message.Header.ID
					resultType = question.Type
					resultClass = question.Class
					resultQuestionCount = len(message.Questions)
				}
			})

			b.Run("miekg_v1", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(test.data)))
				for b.Loop() {
					// v1 has no question-only unpack option. These packets have no
					// records after the question section, keeping decoded scope equal.
					var message dnsv1.Msg
					if err := message.Unpack(test.data); err != nil {
						b.Fatal(err)
					}
					question := message.Question[0]
					resultName = question.Name
					resultID = message.Id
					resultType = question.Qtype
					resultClass = question.Qclass
					resultQuestionCount = len(message.Question)
				}
			})

			b.Run("miekg_v2", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(test.data)))
				for b.Loop() {
					message := dnsv2.Msg{Data: test.data}
					message.Options = dnsv2.MsgOptionUnpackQuestion
					if err := message.Unpack(); err != nil {
						b.Fatal(err)
					}
					question := message.Question[0]
					header := question.Header()
					// v2's presentation name is intentionally allowed to be lossy here;
					// this benchmark measures its normal question-only decode path.
					resultName = header.Name
					resultID = message.ID
					resultType = dnsv2.RRToType(question)
					resultClass = header.Class
					resultQuestionCount = len(message.Question)
				}
			})
		})
	}
}

func singleQuestion(labels [][]byte) []byte {
	data := header(1)
	data = append(data, name(labels...)...)
	data = binary.BigEndian.AppendUint16(data, 1)
	return binary.BigEndian.AppendUint16(data, 1)
}

func compressedQuestions() []byte {
	data := header(3)
	firstName := len(data)
	data = append(data, name([]byte("example"), []byte("com"))...)
	com := firstName + 8
	data = binary.BigEndian.AppendUint16(data, 1)
	data = binary.BigEndian.AppendUint16(data, 1)

	data = append(data, 0xc0, byte(firstName))
	data = binary.BigEndian.AppendUint16(data, 28)
	data = binary.BigEndian.AppendUint16(data, 1)

	data = append(data, 3, 'w', 'w', 'w', 0xc0, byte(com))
	data = binary.BigEndian.AppendUint16(data, 15)
	return binary.BigEndian.AppendUint16(data, 1)
}

func header(questions uint16) []byte {
	data := make([]byte, dnswire.HeaderSize)
	binary.BigEndian.PutUint16(data[2:4], 0x8180)
	binary.BigEndian.PutUint16(data[4:6], questions)
	return data
}

func name(labels ...[]byte) []byte {
	var data []byte
	for _, label := range labels {
		data = append(data, byte(len(label)))
		data = append(data, label...)
	}
	return append(data, 0)
}
