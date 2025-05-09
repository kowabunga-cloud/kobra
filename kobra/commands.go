/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"os"

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"

	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "kobra",
	Short: "Kobra - DevOps deployment swiss-army knife utility",
}

func ParseCommands() {
	if err := RootCmd.Execute(); err != nil {
		klog.Errorf("Whoops. There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}
