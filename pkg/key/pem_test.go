package key

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type PEMTest struct {
	Password string
}

func TestPEM(t *testing.T) {
	cases := []PEMTest{
		{
			Password: "",
		},
		{
			Password: "123456",
		},
	}

	for _, c := range cases {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		assert.Nil(t, err)

		var password, salt []byte
		if c.Password != "" {
			password, salt, err = GenerateKDFKey([]byte(c.Password), nil)
			assert.Nil(t, err)
		}

		privBuf, err := EncodePrivToPem(priv, password, salt, "test")
		assert.Nil(t, err)

		fmt.Println(string(privBuf))

		ret, err := ParsePrivFromPem(privBuf, []byte(c.Password))
		assert.Nil(t, err)
		assert.NotNil(t, ret)
	}
}
