package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/stretchr/testify/assert"
)

type LicenseV1Test struct {
	Flag byte
}

func TestLicenseV1(t *testing.T) {
	privR, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)
	pubR := &privR.PublicKey

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)

	id, err := gonanoid.New()
	assert.Nil(t, err)

	auths := []*AuthV1{
		{
			Code:    "id",
			Name:    "ID",
			Content: id,
		},
	}

	cases := []LicenseV1Test{
		{
			Flag: LicenseV1FlagRaw,
		},
		{
			Flag: LicenseV1FlagCiphertext,
		},
		{
			Flag: LicenseV1FlagRaw | LicenseV1FlagCiphertext,
		},
	}

	for _, c := range cases {
		data, err := BuildLicenseV1(auths, priv, privR, c.Flag)
		assert.Nil(t, err)

		//os.WriteFile(fmt.Sprintf("%d.dat", i), data, 0666)

		if c.Flag&LicenseV1FlagRaw > 0 {
			assert.True(t, bytes.Contains(data, []byte(id)))
		}
		if c.Flag&LicenseV1FlagCiphertext > 0 && c.Flag&LicenseV1FlagRaw == 0 {
			assert.False(t, bytes.Contains(data, []byte(id)))
		}

		l, err := ParseLicenseV1(data, pub, pubR)
		assert.Nil(t, err)
		assert.NotNil(t, l)
		assert.Equal(t, auths, l.Auths)
	}
}
