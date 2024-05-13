package key

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type RSATest struct {
	In  *GenerateRSAReq
	Out error
}

func TestGenerateRSA(t *testing.T) {
	cases := []RSATest{
		{
			In: &GenerateRSAReq{
				Bits: 4096,
			},
			Out: nil,
		},
		{
			In: &GenerateRSAReq{
				Bits:     4096,
				Password: "123456",
			},
			Out: nil,
		},
	}

	for _, c := range cases {
		err := GenerateRSA(c.In)
		assert.True(t, c.Out == err)

		os.Remove("id_rsa.pem")
		os.Remove("id_rsa.pub.pem")
	}
}
