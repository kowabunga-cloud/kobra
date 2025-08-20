/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"fmt"
	"slices"

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
	"github.com/spf13/cobra"
)

const (
	cmdTf             = "tf [cmd] where"
	cmdTfDesc         = "Run OpenTofu/Terraform commands"
	cmdTfFreeArgsDesc = "Tips: Use -- [ARGS] to extend it with free args"
	cmdTfError        = "OpenTofu/Terraform"

	// TF sub-commands
	cmdTfApply    = "apply"
	cmdTfDestroy  = "destroy"
	cmdTfGet      = "get"
	cmdTfImport   = "import"
	cmdTfInit     = "init"
	cmdTfOutput   = "output"
	cmdTfPlan     = "plan"
	cmdTfRefresh  = "refresh"
	cmdTfShow     = "show"
	cmdTfState    = "state"
	cmdTfValidate = "validate"

	tfModuleDesc      = "Restrict TF usage to the specified module"
	tfResourceDesc    = "Restrict TF usage to the specified resource"
	tfOutputDesc      = "Output TF plan to the specified file"
	tfAutoApproveDesc = "Automatically approves (WARNING: use it at your own risk)"
	tfYesDesc         = "Yes we can ! Bypass all checks and run nonetheless."
)

var tfSubCommands = map[string]string{
	cmdTfApply:    "Create or update infrastructure",
	cmdTfDestroy:  "Destroy previously-created infrastructure",
	cmdTfGet:      "Install or upgrade remote TF modules",
	cmdTfImport:   "Associate existing infrastructure with a TF resource",
	cmdTfInit:     "Prepare your working directory for other commands",
	cmdTfOutput:   "Show output values from your root module",
	cmdTfPlan:     "Show changes required by the current configuration",
	cmdTfRefresh:  "Update the state to match remote systems",
	cmdTfShow:     "Show the current state or a saved plan",
	cmdTfState:    "Advanced state management",
	cmdTfValidate: "Check whether the configuration is valid",
}

var tfCmd = &cobra.Command{
	Use:   cmdTf,
	Short: cmdTfDesc,
	Long:  fmt.Sprintf("%s\n  %s", cmdTfDesc, cmdTfFreeArgsDesc),
}

func NewTfSubCommand(name, desc string) *cobra.Command {
	var toolchainUpdate bool
	var tfModule string
	var tfResource string
	var tfOutput string
	var tfAuto bool
	var tfYes bool

	sub := &cobra.Command{
		Use:   name,
		Short: desc,
		Run: func(cmd *cobra.Command, args []string) {
			cfg := GetConfig()
			err := RunTF(&cfg, toolchainUpdate, name, tfModule, tfResource, tfOutput, tfAuto, tfYes, args)
			if err != nil {
				klog.Fatalf(cmdFailureStatus, cmdTfError)
			}
		},
	}

	sub.Flags().BoolVarP(&toolchainUpdate, "update-toolchain", "", false, cmdToolchainUpdateDesc)
	sub.Flags().BoolVarP(&tfYes, "yes", "y", false, tfYesDesc)

	if slices.Contains([]string{cmdTfApply, cmdTfDestroy, cmdTfPlan}, name) {
		sub.Flags().StringVarP(&tfModule, "module", "m", "", tfModuleDesc)
		sub.Flags().StringVarP(&tfResource, "resource", "r", "", tfResourceDesc)
	}

	if slices.Contains([]string{cmdTfOutput, cmdTfPlan}, name) {
		sub.Flags().StringVarP(&tfOutput, "output", "o", "", tfOutputDesc)
	}

	if slices.Contains([]string{cmdTfApply, cmdTfDestroy}, name) {
		sub.Flags().BoolVarP(&tfAuto, "auto", "a", false, tfAutoApproveDesc)
	}

	return sub
}

func init() {
	for sub, desc := range tfSubCommands {
		tfCmd.AddCommand(NewTfSubCommand(sub, desc))
	}
	RootCmd.AddCommand(tfCmd)
}
