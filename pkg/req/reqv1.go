package req

import (
	"bytes"
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
	"superlicense/pkg/mark"

	"github.com/pkg/errors"
)

const (
	ReqV1VersionStr            = "v1"
	ReqV1Version        uint32 = 1
	ReqV1FlagRaw        byte   = 1 << 0
	ReqV1FlagCiphertext byte   = 1 << 1
)

var (
	ReqV1Magic = []byte("superlicense") // 12
	reqV1Lable = []byte("superlicense") // for rsa OAEP
)

// sign: ed25515
// hash: sha256
// encrypt: [ras]
/*
req schema:
- magic: "superlicense"
- version(uint32): 1
- flag: byte : raw|ciphertext
- raw_len(uint64)
- raw_data: base on raw_len
- key_len(uint16)
- key_data: base on key_len
- ciphertext_len(uint64)
- ciphertext: base on ciphertext_len

> version and xxx_len use bigendian
*/
type ReqV1 struct {
	// header
	Magic   []byte
	Version uint32

	// data
	Flag       byte
	Raw        []byte
	CipherKey  []byte
	Ciphertext []byte
	Marks      []*mark.Mark // from Raw/Ciphertext
}

func ParseReqV1File(p string, privR *rsa.PrivateKey) (*ReqV1, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, errors.Wrap(err, "load license req")
	}

	raw, err := base64.URLEncoding.DecodeString(string(data))
	if err != nil {
		return nil, errors.Wrap(err, "decode license req")
	}

	return ParseReqV1(raw, privR)
}

func ParseReqV1(raw []byte, privR *rsa.PrivateKey) (*ReqV1, error) {
	if len(raw) < len(ReqV1Magic)+5 { // 18 = Magic + Version + flag
		return nil, errors.New("invalid license req header")
	}

	r := &ReqV1{}

	// parse magic, version
	r.Magic = raw[:len(ReqV1Magic)]
	r.Version = binary.BigEndian.Uint32(raw[len(ReqV1Magic) : len(ReqV1Magic)+4])
	if !bytes.Equal(r.Magic, ReqV1Magic) {
		return nil, errors.New("invalid license req magic")
	}
	if r.Version != ReqV1Version {
		return nil, errors.New("invalid license req version")
	}

	r.Flag = raw[len(ReqV1Magic)+4]

	data := raw[len(ReqV1Magic)+5:]
	//os.WriteFile(fmt.Sprintf("%s.raw", "cdata"), data, 0666)
	if r.Flag&ReqV1FlagRaw > 0 {
		if len(data) < 8 {
			return nil, errors.New("invalid license req raw data len")
		}

		rl := binary.BigEndian.Uint64(data[:8])
		if len(data) < 8+int(rl) {
			return nil, errors.New("invalid license req raw data")
		}

		r.Raw = data[8 : 8+int(rl)]
		if len(r.Raw) == 0 {
			return nil, errors.New("missing license req raw data")
		}

		data = data[8+int(rl):]
	}
	if r.Flag&ReqV1FlagCiphertext > 0 {
		if privR == nil {
			return nil, errors.New("missing key")
		}

		// parse key
		if len(data) < 2 {
			return nil, errors.New("invalid license req key data len")
		}

		kl := binary.BigEndian.Uint16(data[:2])
		if len(data) < 2+int(kl) {
			return nil, errors.New("invalid license req key data")
		}

		r.CipherKey = data[2 : 2+int(kl)]
		if len(r.CipherKey) == 0 {
			return nil, errors.New("missing license req key data")
		}

		//os.WriteFile(fmt.Sprintf("%s.raw", "cdata.k"), r.CipherKey, 0666)

		data = data[2+int(kl):]

		// parse ciphertext
		if len(data) < 8 {
			return nil, errors.New("invalid license req ciphertext data len")
		}

		cl := binary.BigEndian.Uint64(data[:8])
		if len(data) < 8+int(cl) {
			return nil, errors.New("invalid license req ciphertext data")
		}

		r.Ciphertext = data[8 : 8+int(cl)]
		if len(r.Ciphertext) == 0 {
			return nil, errors.New("missing license req ciphertext data")
		}

		if data = data[8+int(cl):]; len(data) != 0 {
			return nil, errors.New("invalid data remain")
		}

		if len(r.Ciphertext) < 12 {
			return nil, errors.New("invalid license req ciphertext data missing part")
		}

		key, err := rsa.DecryptOAEP(sha256.New(), nil, privR, r.CipherKey, reqV1Lable)
		if err != nil {
			return nil, errors.Wrap(err, "get key")
		}

		r.Raw = aes.AesGcmDecrypt(key, r.Ciphertext[12:], r.Ciphertext[:12])
	}

	if err := json.Unmarshal(r.Raw, &r.Marks); err != nil {
		return nil, errors.Wrap(err, "parse license req marks")
	}

	return r, nil
}

func BuildReqV1File(licFpath string, marks []*mark.Mark, pubR *rsa.PublicKey, flag byte) error {
	data, err := BuildReqV1(marks, pubR, flag)
	if err != nil {
		return err
	}

	raw := base64.URLEncoding.EncodeToString(data)
	if err = os.WriteFile(licFpath, []byte(raw), 0666); err != nil {
		return errors.Wrap(err, "save license req")
	}

	return nil
}

func BuildReqV1(marks []*mark.Mark, pubR *rsa.PublicKey, flag byte) ([]byte, error) {
	if flag&ReqV1FlagRaw == 0 && flag&ReqV1FlagCiphertext == 0 {
		return nil, errors.New("invalid flag")
	}

	jdata, err := json.Marshal(marks)
	if err != nil {
		return nil, errors.Wrap(err, "marshal marks")
	}

	var keyData []byte
	var CiphertextData []byte

	if flag&ReqV1FlagCiphertext > 0 {
		if pubR == nil {
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

		keyData, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pubR, key, reqV1Lable)
		if err != nil {
			return nil, errors.Wrap(err, "encrypt key")
		}

		if len(keyData) > math.MaxUint16 {
			panic("keyData over MaxUint16")
		}

		//os.WriteFile(fmt.Sprintf("%s.raw", "key"), keyData, 0666)
	}

	cdata := bytes.NewBuffer(nil) // license req data
	cdata.WriteByte(flag)

	if flag&ReqV1FlagRaw > 0 {
		l := make([]byte, 8)
		binary.BigEndian.PutUint64(l, uint64(len(jdata)))

		cdata.Write(l)
		cdata.Write(jdata)
	}

	if flag&ReqV1FlagCiphertext > 0 {
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
	data.Write(ReqV1Magic)

	version := make([]byte, 4)
	binary.BigEndian.PutUint32(version, ReqV1Version)
	data.Write(version)

	data.Write(cdata.Bytes())

	return data.Bytes(), nil
}
