/*
 * Copyright (c) Cinemo GmbH. All rights reserved.
 *
 * This file is proprietary and confidential. Unauthorized copying,
 * distribution, or use, via any medium, is strictly prohibited without
 * prior written permission from Cinemo GmbH.
 */

package ipsctl

import (
	"fmt"

	"github.com/spf13/cobra"
)

var version = "was not built correctly" // set via the Makefile

var versionCmd = &cobra.Command{
	Use:     "version",
	Aliases: []string{"vers"},
	Short:   "Display IPSctl version number",
	Args:    cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s\n", version)
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
