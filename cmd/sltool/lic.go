package main

import (
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"os"

	"superlicense/pkg/key"
	"superlicense/pkg/license"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var (
	licFpath           string
	licVersion         string
	licSignPemPath     string
	licEncPemPath      string
	licSignPemPassword string
	licEncPemPassword  string
	licDecPemPath      string
)

var (
	// only for build license example
	build = &cobra.Command{
		Use:   "build",
		Short: "build license",
		RunE:  BuildRun,
	}

	parse = &cobra.Command{
		Use:   "parse",
		Short: "parse license",
		RunE:  ParseRun,
	}
)

func init() {
	build.PersistentFlags().StringVarP(&licVersion, "version", "v", "v1", "license version")
	build.PersistentFlags().StringVarP(&licSignPemPath, "signkey", "p", "id_ed25519.pem", "private key for sign")
	build.PersistentFlags().StringVarP(&licEncPemPath, "enckey", "e", "id_rsa.pem", "private key for encrypt")
	build.PersistentFlags().StringVarP(&licSignPemPassword, "signpassword", "m", "", "password for sign private key")
	build.PersistentFlags().StringVarP(&licEncPemPassword, "encpassword", "n", "", "password for encrypt private key")
	build.PersistentFlags().StringVarP(&licFpath, "path", "l", "license.dat", "license path")

	parse.PersistentFlags().StringVarP(&licVersion, "version", "v", "v1", "license version")
	parse.PersistentFlags().StringVarP(&licFpath, "path", "l", "license.dat", "license path")
	parse.PersistentFlags().StringVarP(&licSignPemPath, "signkey", "p", "id_ed25519.pub.pem", "public key for verify sign")
	parse.PersistentFlags().StringVarP(&licDecPemPath, "deckey", "d", "id_rsa.pub.pem", "public key for decrypt")
}

func BuildRun(cmd *cobra.Command, args []string) error {
	switch licVersion {
	case "v1":
		signPemData, _ := os.ReadFile(licSignPemPath)
		signPriv, err := key.ParsePrivFromPem(signPemData, []byte(licSignPemPassword))
		if err != nil {
			return errors.Wrap(err, "load private key for sign")
		}

		var encPriv *rsa.PrivateKey
		if licEncPemPath != "" {
			encPemData, _ := os.ReadFile(licEncPemPath)
			encPrivAny, err := key.ParsePrivFromPem(encPemData, []byte(licEncPemPassword))
			if err != nil {
				return errors.Wrap(err, "load private key for encrypt")
			}
			encPriv = encPrivAny.(*rsa.PrivateKey)
		}

		auths := []license.AuthV1{
			{
				Code:    "id",
				Name:    "ID",
				Content: "test",
			},
		}

		flag := license.LicenseV1FlagRaw
		if encPriv != nil {
			flag |= license.LicenseV1FlagCiphertext
		}

		data, err := license.BuildLicenseV1(auths, signPriv.(*ed25519.PrivateKey), encPriv, flag)
		if err != nil {
			return errors.Wrap(err, "build license")
		}

		raw := base64.URLEncoding.EncodeToString(data)
		if err = os.WriteFile(licFpath, []byte(raw), 0666); err != nil {
			return errors.Wrap(err, "save license")
		}

		fmt.Println(fmt.Sprintf("build license ok: %s", licFpath))

		return nil
	default:
		return errors.New("unsupport license version")
	}
}

func ParseRun(cmd *cobra.Command, args []string) error {
	switch licVersion {
	case "v1":
		signPemData, _ := os.ReadFile(licSignPemPath)
		signPub, err := key.ParsePubFromPem(signPemData)
		if err != nil {
			return errors.Wrap(err, "load public key for verify sign")
		}

		var decPub *rsa.PublicKey
		if licDecPemPath != "" {
			decPemData, _ := os.ReadFile(licDecPemPath)
			decPubAny, err := key.ParsePubFromPem(decPemData)
			if err != nil {
				return errors.Wrap(err, "load public key for decrypt")
			}
			decPub = decPubAny.(*rsa.PublicKey)
		}

		l, err := license.ParseLicenseV1File(licFpath, signPub.(*ed25519.PublicKey), decPub)
		if err != nil {
			return errors.Wrap(err, "parse license")
		}

		spew.Dump(l.Auths)

		return nil
	default:
		return errors.New("unsupport license version")
	}
}
