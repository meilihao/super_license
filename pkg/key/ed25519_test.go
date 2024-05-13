package key

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type Ed25519Test struct {
	In  *GenerateEd25519Req
	Out error
}

func TestGenerateEd25519(t *testing.T) {
	cases := []Ed25519Test{
		{
			In:  &GenerateEd25519Req{},
			Out: nil,
		},
		{
			In: &GenerateEd25519Req{
				Password: "123456",
			},
			Out: nil,
		},
	}

	for _, c := range cases {
		err := GenerateEd25519(c.In)
		assert.True(t, c.Out == err)

		os.Remove("id_ed25519.pem")
		os.Remove("id_ed25519.pub.pem")
	}
}
