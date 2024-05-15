package license

import (
	"regexp"
	"time"

	"github.com/pkg/errors"
)

// AuthV1设计:
// - kv形式: 扩展性极佳, 改动少
// - 带ExpiredAt: 支持单独设置过期时间
// - Name,Remark: 单纯为了展示
type AuthV1 struct {
	Code      string
	Content   string `json:",omitempty"`
	ExpiredAt int64  `json:",omitempty"` // 0, is no expire
	Name      string `json:",omitempty"`
	Remark    string `json:",omitempty"`
}

type AuthV1Check struct {
	Requred        bool
	Code           string
	Name           string                    // inject to license
	Remark         string                    // inject to license
	Check          func(string, int64) error `json:"-"`
	RequredExpired bool
	RequredContent bool
	Example        string
	Tip            string
}

func GenerateAuthV1s(checks []*AuthV1Check, auths []*AuthV1) ([]*AuthV1, error) {
	am := make(map[string]*AuthV1, len(auths))
	for _, a := range auths {
		if am[a.Code] != nil {
			return nil, errors.Errorf("double Auth: %s", a.Code)
		}

		am[a.Code] = a
	}

	cm := make(map[string]*AuthV1Check, len(checks))
	for _, c := range checks {
		cm[c.Code] = c
	}

	for _, c := range cm {
		if am[c.Code] == nil && c.Requred {
			return nil, errors.Errorf("missing Required Auth: %s", c.Code)
		}
	}

	var err error
	var c *AuthV1Check
	nauths := make([]*AuthV1, 0, len(auths)) // new auths

	for _, a := range auths {
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

		nauths = append(nauths, t)
	}

	return nauths, nil
}

const (
	AuthV1CodeIsTry     = "is_try"
	AuthV1CodeExpiredAt = "expired_at"
	AuthV1CodeModel     = "model"
)

func WithTry() *AuthV1Check {
	return &AuthV1Check{
		Requred: false,
		Code:    AuthV1CodeIsTry,
		Name:    "是否试用",
		Check: func(content string, expiredAt int64) error {
			if content != "t" && content != "f" {
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
		Requred: true,
		Code:    AuthV1CodeExpiredAt,
		Name:    "过期时间",
		Remark:  "timestamp",
		Check: func(content string, expiredAt int64) error {
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
		Requred: false,
		Code:    AuthV1CodeModel,
		Name:    "适配型号",
		Check: func(content string, expiredAt int64) error {
			r := regexp.MustCompile(`^X[0-9]{3}$`)
			if !r.MatchString(content) {
				return errors.New("invalid content by regexp")
			}

			return nil
		},
		RequredContent: true,
		Example:        "X100",
		Tip:            `^X[0-9]{3}$`,
	}
}
