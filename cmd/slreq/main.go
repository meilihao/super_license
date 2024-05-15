package main

import (
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{Use: "slreq"}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&reqVersion, "version", "v", "v1", "req version")
	rootCmd.PersistentFlags().StringVarP(&reqFpath, "path", "l", "req.dat", "req path")
}

func main() {
	rootCmd.AddCommand(build)
	rootCmd.AddCommand(parse)
	rootCmd.Execute()
}
