package main

import (
	"superlicense/pkg/key"

	"github.com/spf13/cobra"
)

var (
	keyType     string
	keyPassword string
	keyFpath    string
	keyBits     int
	keyComment  string

	keygen = &cobra.Command{
		Use:   "keygen",
		Short: "generate key",
		RunE:  KeygenRun,
	}
)

func init() {
	keygen.PersistentFlags().StringVarP(&keyType, "type", "t", "rsa", "rsa, ed25519")
	keygen.PersistentFlags().StringVarP(&keyPassword, "password", "P", "", "")
	keygen.PersistentFlags().StringVarP(&keyFpath, "filename", "f", "", "the filename of the key file")
	keygen.PersistentFlags().IntVarP(&keyBits, "bits", "b", 4096, "the  number  of  bits in the key to creat, only for rsa")
	keygen.PersistentFlags().StringVarP(&keyComment, "comment", "C", "", "")
}

func KeygenRun(cmd *cobra.Command, args []string) error {
	switch keyType {
	case key.TypeEd25519:
		return key.GenerateEd25519(&key.GenerateEd25519Req{
			Password: keyPassword,
			Fpath:    keyFpath,
			Commont:  keyComment,
		})
	case key.TypeRSA:
		return key.GenerateRSA(&key.GenerateRSAReq{
			Bits:     keyBits,
			Password: keyPassword,
			Fpath:    keyFpath,
			Commont:  keyComment,
		})
	default:
		return key.ErrTypeInvalid
	}
}
