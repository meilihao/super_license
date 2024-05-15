package main

import (
	"crypto/rsa"
	"fmt"
	"os"

	"superlicense/pkg/key"
	"superlicense/pkg/mark"
	"superlicense/pkg/req"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var (
	reqFpath   string
	reqVersion string

	reqEncPemPath string

	reqDecPemPath     string
	reqDecPemPassword string
)

var (
	// only for build license req example
	build = &cobra.Command{
		Use:   "build",
		Short: "build license req",
		RunE:  BuildRun,
	}

	parse = &cobra.Command{
		Use:   "parse",
		Short: "parse license req",
		RunE:  ParseRun,
	}
)

func init() {
	build.PersistentFlags().StringVarP(&reqEncPemPath, "enckey", "e", "id_rsa.pub.pem", "public key for encrypt")

	parse.PersistentFlags().StringVarP(&reqDecPemPath, "deckey", "d", "id_rsa.pem", "private key for decrypt")
	parse.PersistentFlags().StringVarP(&reqDecPemPassword, "decpassword", "n", "", "password for private key")
}

func BuildRun(cmd *cobra.Command, args []string) error {
	switch reqVersion {
	case req.ReqV1VersionStr:
		fmt.Println("use license req:" + req.ReqV1VersionStr)

		var err error
		var encPub *rsa.PublicKey
		if reqEncPemPath != "" {
			fmt.Println("use enckey:" + reqEncPemPath)

			encPemData, _ := os.ReadFile(reqEncPemPath)
			encPubAny, err := key.ParsePubFromPem(encPemData)
			if err != nil {
				return errors.Wrap(err, "load public key for encrypt")
			}
			encPub = encPubAny.(*rsa.PublicKey)
		}

		marks := []*mark.Mark{
			mark.WithMachineId(),
		}

		flag := req.ReqV1FlagRaw
		if encPub != nil {
			flag |= req.ReqV1FlagCiphertext
		}

		err = req.BuildReqV1File(reqFpath, marks, encPub, flag)
		if err != nil {
			return errors.Wrap(err, "build license req")
		}

		fmt.Printf("build license req ok: %s\n", reqFpath)

		return nil
	default:
		return req.ErrUnsupportVersion
	}
}

func ParseRun(cmd *cobra.Command, args []string) error {
	switch reqVersion {
	case req.ReqV1VersionStr:
		fmt.Println("use license req:" + req.ReqV1VersionStr)

		var err error
		var decPriv *rsa.PrivateKey
		if reqDecPemPath != "" {
			fmt.Println("use deckey:" + reqDecPemPath)

			decPemData, _ := os.ReadFile(reqDecPemPath)
			decPrivAny, err := key.ParsePrivFromPem(decPemData, []byte(reqDecPemPassword))
			if err != nil {
				return errors.Wrap(err, "load private key for decrypt")
			}
			decPriv = decPrivAny.(*rsa.PrivateKey)
		}

		r, err := req.ParseReqV1File(reqFpath, decPriv)
		if err != nil {
			return errors.Wrap(err, "parse license req")
		}

		spew.Dump(r.Marks)

		return nil
	default:
		return req.ErrUnsupportVersion
	}
}
