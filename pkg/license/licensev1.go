package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"os"

	"superlicense/pkg/lib/aes"

	"github.com/meilihao/gorsa"
	"github.com/pkg/errors"
)

const (
	LicenseV1Version        uint32 = 1
	LicenseV1FlagRaw        byte   = 1 << 0
	LicenseV1FlagCiphertext byte   = 1 << 1
)

var (
	LicenseV1Magic = []byte("superlicense") // 12
)

// sign: ed25515
// hash: sha256
// encrypt: [ras]
/*
license schema:
- magic: "superlicense"
- version(uint32): 1
- sign_len:uint16
- Sign_data
- flag: byte : raw|ciphertext
- raw_len(uint64)
- raw_data: base on raw_len
- key_len(uint16)
- key_data: base on key_len
- ciphertext_len(uint64)
- ciphertext: base on ciphertext_len

> version and xxx_len use bigendian
*/
type LicenseV1 struct {
	// header
	Magic   []byte
	Version uint32
	Sign    []byte

	// data
	Flag       byte
	Raw        []byte
	CipherKey  []byte
	Ciphertext []byte
	Auths      []AuthV1 // from Raw/Ciphertext
}

type AuthV1 struct {
	Code      string
	Name      string `json:",omitempty"`
	Content   string
	ExpiredAt int64 `json:",omitempty"` // 0, is no expire
	Remark    string
}

func ParseLicenseV1File(p string, pub *ed25519.PublicKey, pubR *rsa.PublicKey) (*LicenseV1, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, errors.Wrap(err, "load license")
	}

	raw, err := base64.URLEncoding.DecodeString(string(data))
	if err != nil {
		return nil, errors.Wrap(err, "decode license")
	}

	return ParseLicenseV1(raw, pub, pubR)
}

func ParseLicenseV1(raw []byte, pub *ed25519.PublicKey, pubR *rsa.PublicKey) (*LicenseV1, error) {
	if len(raw) < len(LicenseV1Magic)+4 { // 18 = Magic + Version
		return nil, errors.New("invalid license header")
	}

	l := &LicenseV1{}

	// parse magic, version
	l.Magic = raw[:len(LicenseV1Magic)]
	l.Version = binary.BigEndian.Uint32(raw[len(LicenseV1Magic) : len(LicenseV1Magic)+4])
	if !bytes.Equal(l.Magic, LicenseV1Magic) {
		return nil, errors.New("invalid license magic")
	}
	if l.Version != LicenseV1Version {
		return nil, errors.New("invalid license version")
	}

	// parse sign
	raw = raw[len(LicenseV1Magic)+4:]
	if len(raw) < 2 {
		return nil, errors.New("invalid license sign len")
	}

	sl := binary.BigEndian.Uint16(raw[:2])
	if len(raw) < 2+int(sl) {
		return nil, errors.New("invalid license sign data")
	}
	l.Sign = raw[2 : 2+int(sl)]
	raw = raw[2+int(sl):]

	h := sha256.New()
	h.Write(raw)

	if !ed25519.Verify(*pub, h.Sum(nil), l.Sign) {
		return nil, errors.New("invalid license sign")
	}

	if len(raw) < 1 {
		return nil, errors.New("invalid license flag")
	}

	l.Flag = raw[0]

	data := raw[1:]
	//os.WriteFile(fmt.Sprintf("%s.raw", "cdata"), data, 0666)
	if l.Flag&LicenseV1FlagRaw > 0 {
		if len(data) < 8 {
			return nil, errors.New("invalid license raw data len")
		}

		rl := binary.BigEndian.Uint64(data[:8])
		if len(data) < 8+int(rl) {
			return nil, errors.New("invalid license raw data")
		}

		l.Raw = data[8 : 8+int(rl)]

		data = data[8+int(rl):]
	}
	if l.Flag&LicenseV1FlagCiphertext > 0 {
		if pubR == nil {
			return nil, errors.New("missing key")
		}

		// parse key
		if len(data) < 2 {
			return nil, errors.New("invalid license key data len")
		}

		kl := binary.BigEndian.Uint16(data[:2])
		if len(data) < 2+int(kl) {
			return nil, errors.New("invalid license key data")
		}

		l.CipherKey = data[2 : 2+int(kl)]

		data = data[2+int(kl):]

		// parse ciphertext
		if len(data) < 8 {
			return nil, errors.New("invalid license ciphertext data len")
		}

		cl := binary.BigEndian.Uint64(data[:8])
		if len(data) < 8+int(cl) {
			return nil, errors.New("invalid license ciphertext data")
		}

		l.Ciphertext = data[8 : 8+int(cl)]

		if data = data[8+int(cl):]; len(data) != 0 {
			return nil, errors.New("invalid data remain")
		}

		if len(l.Ciphertext) < 12 {
			return nil, errors.New("invalid license ciphertext data missing part")
		}

		gorsa.RSA.SetPublicKeyV2(pubR)

		key, err := gorsa.RSA.PubKeyDECRYPT(l.CipherKey)
		if err != nil {
			return nil, errors.Wrap(err, "get key")
		}

		l.Raw = aes.AesGcmDecrypt(key, l.Ciphertext[12:], l.Ciphertext[:12])
	}

	if err := json.Unmarshal(l.Raw, &l.Auths); err != nil {
		return nil, errors.Wrap(err, "parse license auths")
	}

	return l, nil
}

func BuildLicenseV1(auths []AuthV1, priv *ed25519.PrivateKey, privR *rsa.PrivateKey, flag byte) ([]byte, error) {
	if flag&LicenseV1FlagRaw == 0 && flag&LicenseV1FlagCiphertext == 0 {
		return nil, errors.New("invalid flag")
	}

	jdata, err := json.Marshal(auths)
	if err != nil {
		return nil, errors.Wrap(err, "marshal auths")
	}

	var keyData []byte
	var CiphertextData []byte

	if flag&LicenseV1FlagCiphertext > 0 {
		if privR == nil {
			return nil, errors.New("missing key")
		}

		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, errors.New("generate key")
		}

		ciphertext, nonce := aes.AesGcmEncrypt(key, jdata)
		CiphertextData = make([]byte, len(ciphertext)+len(nonce))
		copy(CiphertextData, nonce)
		copy(CiphertextData[12:], ciphertext)

		//os.WriteFile(fmt.Sprintf("%s.raw", "ciphertext"), CiphertextData, 0666)

		gorsa.RSA.SetPrivateKeyV2(privR)

		keyData, err = gorsa.RSA.PriKeyENCTYPT(key)
		if err != nil {
			return nil, errors.Wrap(err, "encrypt key")
		}
		if len(keyData) > math.MaxUint16 {
			panic("keyData over MaxUint16")
		}

		//os.WriteFile(fmt.Sprintf("%s.raw", "key"), keyData, 0666)
	}

	cdata := bytes.NewBuffer(nil) // license data
	cdata.WriteByte(flag)

	if flag&LicenseV1FlagRaw > 0 {
		l := make([]byte, 8)
		binary.BigEndian.PutUint64(l, uint64(len(jdata)))

		cdata.Write(l)
		cdata.Write(jdata)
	}

	if flag&LicenseV1FlagCiphertext > 0 {
		kl := make([]byte, 2)
		binary.BigEndian.PutUint16(kl, uint16(len(keyData)))

		cdata.Write(kl)
		cdata.Write(keyData)

		cl := make([]byte, 8)
		binary.BigEndian.PutUint64(cl, uint64(len(CiphertextData)))

		cdata.Write(cl)
		cdata.Write(CiphertextData)
	}

	data := bytes.NewBuffer(nil)
	data.Write(LicenseV1Magic)

	version := make([]byte, 4)
	binary.BigEndian.PutUint32(version, LicenseV1Version)
	data.Write(version)

	// write sign
	h := sha256.New()
	h.Write(cdata.Bytes())

	sign := ed25519.Sign(*priv, h.Sum(nil))
	if len(sign) > math.MaxUint16 {
		panic("sign over MaxUint16")
	}

	sl := make([]byte, 2)
	binary.BigEndian.PutUint16(sl, uint16(len(sign)))
	data.Write(sl)
	data.Write(sign)

	data.Write(cdata.Bytes())

	return data.Bytes(), nil
}
