package license

import (
	"sync"

	"github.com/pkg/errors"
)

type CreateLicenseV1Req struct {
	Name  string
	Auths []*AuthV1
}

type LicenserV1 interface {
	Name() string
	Checks() []*AuthV1Check
	Valid(r *CreateLicenseV1Req) ([]*AuthV1, error)
}

var (
	licenseV1Store = sync.Map{}
)

func RegisterLicenseV1(l LicenserV1) {
	_, isExist := licenseV1Store.Load(l.Name())
	if isExist {
		panic(errors.Errorf("double register: %s", l.Name()))
	}

	cs := l.Checks()
	if len(cs) == 0 {
		panic(errors.Errorf("missing Checks: %s", l.Name()))
	}

	m := make(map[string]bool, len(cs)) // for check double check

	for _, v := range cs {
		if m[v.Code] {
			panic(errors.Errorf("double Check: %s, %s", l.Name(), v.Code))
		}

		m[v.Code] = true
	}

	licenseV1Store.Store(l.Name(), l)
}
