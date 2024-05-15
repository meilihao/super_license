package license

import (
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestLicensev1Demo(t *testing.T) {
	r := &CreateLicenseV1Req{
		Name: "demo",
		Auths: []*AuthV1{
			{
				Code:    AuthV1CodeIsTry,
				Content: "t",
			},
			{
				Code:      AuthV1CodeExpiredAt,
				ExpiredAt: time.Now().Add(time.Hour * 24).Unix(),
			},
			{
				Code:    AuthV1CodeModel,
				Content: "X200",
			},
		},
	}

	li, isExist := licenseV1Store.Load(r.Name)
	assert.True(t, isExist)
	l := li.(LicenserV1)

	auths, err := l.Valid(r)
	assert.Nil(t, err)
	spew.Dump(auths)
}
