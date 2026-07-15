/*
 * Copyright (c) Cinemo GmbH. All rights reserved.
 *
 * Originally licensed under the Apache License, Version 2.0
 * (see https://www.apache.org/licenses/LICENSE-2.0.txt).
 * Benjamin Zores, original author, granted Cinemo GmbH explicit rights
 * to relicense and use this work under proprietary terms.
 *
 * This file is proprietary and confidential. Unauthorized copying,
 * distribution, or use, via any medium, is strictly prohibited without
 * prior written permission from Cinemo GmbH.
 */

package ipsctl

import (
	"os"

	"github.com/kowabunga-cloud/common/klog"

	"github.com/spf13/cobra"
)

const (
	cmdToolchainUpdateDesc = "Check for toolchain update before run"

	cmdFailureStatus = "Something went terribly wrong, unable to run %s or execution came as error !"
)

var RootCmd = &cobra.Command{
	Use:   "ipsctl",
	Short: "IPSctl - DevOps deployment swiss-army knife utility",
}

func ParseCommands() {
	if err := RootCmd.Execute(); err != nil {
		klog.Errorf("Whoops. There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}
