/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"fmt"

	"github.com/spf13/cobra"
)

var version = "was not built correctly" // set via the Makefile

var versionCmd = &cobra.Command{
	Use:     "version",
	Aliases: []string{"vers"},
	Short:   "Display Kobra version number",
	Args:    cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s\n", version)
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
