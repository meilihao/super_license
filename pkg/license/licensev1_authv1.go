package license

import (
	"regexp"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// AuthV1设计:
// - kv形式: 扩展性极佳, 改动少
// - 带ExpiredAt: 支持单独设置过期时间
// - Name,Remark: 单纯为了展示
type AuthV1 struct {
	Code      string
	Name      string `json:",omitempty"`
	Content   string
	ExpiredAt int64 `json:",omitempty"` // 0, is no expire
	Remark    string
}

type CreateLicenseReq struct {
	Name  string
	Auths []*AuthV1
}

type LicenserV1 interface {
	Name() string
	Checks() []*AuthV1Check
	Valid(r *CreateLicenseReq) ([]*AuthV1, error)
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

	m := make(map[string]bool, len(cs)) // for check double req

	for _, v := range cs {
		if m[v.Code] {
			panic(errors.Errorf("double Check: %s, %s", l.Name(), v.Code))
		}

		if v.ReqExp != "" {
			v._Reg = regexp.MustCompile(v.ReqExp)
		}

		m[v.Code] = true
	}

	licenseV1Store.Store(l.Name(), l)
}

type AuthV1Check struct {
	IsRequred      bool
	Code           string
	Name           string // inject to license
	Remark         string // inject to license
	Check          func(string, int64) error
	RequredExpired bool
	RequredContent bool
	Example        string
	Tip            string
	ReqExp         string
	_Reg           *regexp.Regexp
}

func GenerateAuthV1s(checks []*AuthV1Check, r *CreateLicenseReq) ([]*AuthV1, error) {
	rm := make(map[string]*AuthV1, len(r.Auths))
	for _, r := range r.Auths {
		if rm[r.Code] != nil {
			return nil, errors.Errorf("double Auth: %s", r.Code)
		}

		rm[r.Code] = r
	}

	cm := make(map[string]*AuthV1Check, len(checks))
	for _, c := range checks {
		cm[c.Code] = c
	}

	for _, c := range cm {
		if rm[c.Code] == nil && c.IsRequred {
			return nil, errors.Errorf("missing Required Auth: %s", c.Code)
		}
	}

	var err error
	var c *AuthV1Check
	auths := make([]*AuthV1, 0, len(r.Auths))

	for _, a := range r.Auths {
		c = cm[a.Code]
		if c == nil {
			return nil, errors.Errorf("unsupport Auth: %s", a.Code)
		}

		t := &AuthV1{
			Code:      a.Code,
			Name:      c.Name,
			Remark:    c.Remark,
			Content:   a.Content,
			ExpiredAt: a.ExpiredAt,
		}

		if c._Reg != nil {
			if !c._Reg.MatchString(t.Content) {
				return nil, errors.Errorf("Reg Check Auth failed: %s", t.Code)
			}
		}

		if !c.RequredExpired {
			t.ExpiredAt = 0
		}

		if !c.RequredContent {
			t.Content = ""
		}

		if c.RequredContent || c.RequredExpired {
			if err = c.Check(t.Content, t.ExpiredAt); err != nil {
				return nil, err
			}
		}

		auths = append(auths, t)
	}

	return auths, nil
}

const (
	AuthV1CodeIsTry     = "is_try"
	AuthV1CodeExpiredAt = "expired_at"
	AuthV1CodeModel     = "model"
)

func WithTry() *AuthV1Check {
	return &AuthV1Check{
		IsRequred: false,
		Code:      AuthV1CodeIsTry,
		Name:      "是否试用",
		Check: func(value string, expiredAt int64) error {
			if value != "t" && value != "f" {
				return errors.New("need t or f")
			}

			return nil
		},
		RequredContent: true,
		Example:        "t|f",
	}
}

func WithExpiredAt() *AuthV1Check {
	return &AuthV1Check{
		IsRequred: true,
		Code:      AuthV1CodeExpiredAt,
		Name:      "过期时间",
		Remark:    "timestamp",
		Check: func(value string, expiredAt int64) error {
			now := time.Now().Unix()

			if expiredAt <= now {
				return errors.New("before now")
			}

			return nil
		},
		RequredExpired: true,
		RequredContent: false,
		Example:        "2006-01-02 15:04:05",
	}
}

func WithModel() *AuthV1Check {
	return &AuthV1Check{
		IsRequred: false,
		Code:      AuthV1CodeModel,
		Name:      "适配型号",
		Check: func(value string, expiredAt int64) error {
			return nil
		},
		RequredContent: true,
		Example:        "X100",
		ReqExp:         `^X[0-9]{3}$`,
	}
}