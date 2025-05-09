/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
	"github.com/spf13/cobra"
)

const (
	cmdSetup      = "setup"
	cmdSetupDesc  = "Setup a proper deployment environment (download/install/upgrade 3rd-party plugins)"
	cmdSetupError = "get 3rd-party plugins deployment software"

	setupForceDesc = "Force download/upgrade of plugins"
	setupCleanDesc = "Cleanup/trash the whole plugins directory before setup"
)

var setupForce bool
var setupClean bool

var setupCmd = &cobra.Command{
	Use:   cmdSetup,
	Short: cmdSetupDesc,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := GetConfig()
		err := RunSetup(&cfg, setupForce, setupClean)
		if err != nil {
			klog.Fatalf(cmdFailureStatus, cmdSetupError)
		}
	},
}

func init() {
	setupCmd.Flags().BoolVarP(&setupForce, "force", "f", false, setupForceDesc)
	setupCmd.Flags().BoolVarP(&setupClean, "clean", "c", false, setupCleanDesc)
	RootCmd.AddCommand(setupCmd)
}
