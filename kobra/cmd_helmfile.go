/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"fmt"

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
	"github.com/spf13/cobra"
)

const (
	cmdHf             = "helmfile [cmd] where"
	cmdHfDesc         = "Run Helmfile commands"
	cmdHfFreeArgsDesc = "Tips: Use -- [ARGS] to extend it with free args"
	cmdHfError        = "Helmfile"

	// Helmfile sub-commands
	cmdHfApply    = "apply"
	cmdHfBuild    = "build"
	cmdHfDeps     = "deps"
	cmdHfDestroy  = "destroy"
	cmdHfDiff     = "diff"
	cmdHfFetch    = "fetch"
	cmdHfInit     = "init"
	cmdHfList     = "list"
	cmdHfRepos    = "repos"
	cmdHfStatus   = "status"
	cmdHfSync     = "sync"
	cmdHfTemplate = "template"

	hfVerboseDesc = "Enabled extra verbosity/debug"
	hfYesDesc     = "Yes we can ! Bypass all checks and deploy nonetheless."
	hfReleaseDesc = "Name of the specific Helm release to be used"
)

var hfSubCommands = map[string]string{
	cmdHfApply:    "Apply all resources from state file only when there are changes",
	cmdHfBuild:    "Build all resources from state file",
	cmdHfDeps:     "Update charts based on their requirements",
	cmdHfDestroy:  "Destroys and then purges releases",
	cmdHfDiff:     "Diff releases defined in state file",
	cmdHfFetch:    "Fetch charts from state file",
	cmdHfInit:     "Initialize the helmfile, includes version checking and installation of helm and plug-ins",
	cmdHfList:     "List releases defined in state file",
	cmdHfRepos:    "Add chart repositories defined in state file",
	cmdHfStatus:   "Retrieve status of releases in state file",
	cmdHfSync:     "Sync releases defined in state file",
	cmdHfTemplate: "Template releases defined in state file",
}

var hfCmd = &cobra.Command{
	Use:     cmdHf,
	Short:   cmdHfDesc,
	Aliases: []string{"hf"},
	Long:    fmt.Sprintf("%s\n  %s", cmdHfDesc, cmdHfFreeArgsDesc),
}

func NewHfSubCommand(name, desc string) *cobra.Command {
	var hfVerbose bool
	var hfYes bool
	var hfRelease string

	sub := &cobra.Command{
		Use:   name,
		Short: desc,
		Run: func(cmd *cobra.Command, args []string) {
			cfg := GetConfig()
			err := RunHelmfile(&cfg, name, hfVerbose, hfYes, hfRelease, args)
			if err != nil {
				klog.Fatalf(cmdFailureStatus, fmt.Sprintf("%s %s", cmdHfError, name))
			}
		},
	}

	sub.Flags().BoolVarP(&hfVerbose, "verbose", "v", false, hfVerboseDesc)
	sub.Flags().BoolVarP(&hfYes, "yes", "y", false, hfYesDesc)
	sub.Flags().StringVarP(&hfRelease, "release", "r", "", hfReleaseDesc)

	return sub
}

func init() {
	for sub, desc := range hfSubCommands {
		hfCmd.AddCommand(NewHfSubCommand(sub, desc))
	}
	RootCmd.AddCommand(hfCmd)
}
