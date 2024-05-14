package license

func init() {
	ReisterLicenseV1Demo()
}

type LicenseV1Demo struct {
	checks []*AuthV1Check
}

func (l *LicenseV1Demo) Name() string {
	return "demo"
}

func (l *LicenseV1Demo) Checks() []*AuthV1Check {
	return l.checks
}

func (l *LicenseV1Demo) Valid(r *CreateLicenseReq) ([]*AuthV1, error) {
	return GenerateAuthV1s(l.checks, r)
}

func ReisterLicenseV1Demo() {
	l := &LicenseV1Demo{
		checks: []*AuthV1Check{
			WithTry(),
			WithExpiredAt(),
			WithModel(),
		},
	}

	RegisterLicenseV1(l)
}
