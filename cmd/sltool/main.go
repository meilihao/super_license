package main

import (
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{Use: "sltool"}

	rootCmd.AddCommand(keygen)
	rootCmd.AddCommand(build)
	rootCmd.AddCommand(parse)
	rootCmd.Execute()
}
