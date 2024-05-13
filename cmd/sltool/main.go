package main

import (
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{Use: "sltool"}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&licVersion, "version", "v", "v1", "license version")
	rootCmd.PersistentFlags().StringVarP(&licFpath, "path", "l", "license.dat", "license path")
}

func main() {
	rootCmd.AddCommand(keygen)
	rootCmd.AddCommand(build)
	rootCmd.AddCommand(parse)
	rootCmd.Execute()
}
