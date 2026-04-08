/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"fmt"

	"github.com/kowabunga-cloud/common/klog"
	"github.com/spf13/cobra"
)

const (
	cmdAnsible             = "ansible"
	cmdAnsibleDesc         = "Run Ansible commands"
	cmdAnsibleFreeArgsDesc = "Tips: Use -- [ARGS] to extend it with free args"
	cmdAnsibleError        = "Ansible"

	cmdAnsiblePull     = "pull"
	cmdAnsiblePullDesc = "Pull Ansible roles/collections requirements without deployment"

	cmdAnsibleDeploy              = "deploy"
	cmdAnsibleDeployDesc          = "Run Ansible playbook"
	cmdAnsibleDeployPlaybookDesc  = "Playbook to be run (path is auto-searched if unspecified, .yml suffix is optional)"
	cmdAnsibleDeployUpgradeDesc   = "Should the roles/collections be updated ?"
	cmdAnsibleDeployCheckDesc     = "Dry-Run, check-only ?"
	cmdAnsibleDeployBootstrapDesc = "Should Ansible run with the bootstrap user/key ?"
	cmdAnsibleDeployLimitDesc     = "Limit execution to specific hosts to be set as 'host1,host2...', comma-separated"
	cmdAnsibleDeployListTagsDesc  = "Display supported Ansible tags"
	cmdAnsibleDeployTagsDesc      = "Ansible tags to be applied, comma-separated"
	cmdAnsibleDeploySkipTagsDesc  = "Ansible tags to be skipped, comma-separated"
	cmdAnsibleDeployExtraVarsDesc = "Ansible extra variables to be set as 'key1=value1 key2=value2' (space-separated)"
	cmdAnsibleDeployVerboseDesc   = "Enabled extra verbosity"
	cmdAnsibleDeploySkipDesc      = "Skip Git checks and and run nonetheless."

	cmdAnsibleInventory              = "inventory"
	cmdAnsibleInventoryActionGraph   = "graph"
	cmdAnsibleInventoryActionHost    = "host"
	cmdAnsibleInventoryActionList    = "list"
	cmdAnsibleInventoryDesc          = "Show Ansible inventory information"
	cmdAnsibleInventoryPlaybookDesc  = "Playbook to be used (path is auto-searched if unspecified, .yml suffix is optional)"
	cmdAnsibleInventoryGroupDesc     = "Group to restrict/filter to"
	cmdAnsibleInventoryHostDesc      = "Host to restrict/filter to"
	cmdAnsibleInventoryOutputDesc    = "Send the inventory to a file instead of to the screen"
	cmdAnsibleInventoryExtraVarsDesc = "Ansible extra variables to be set as 'key1=value1 key2=value2' (space-separated)"
	cmdAnsibleInventoryLimitDesc     = "Limit execution to specific hosts to be set as 'host1,host2...', comma-separated"
	cmdAnsibleInventoryVerboseDesc   = "Enabled extra verbosity"
)

var ansibleCmd = &cobra.Command{
	Use:   cmdAnsible,
	Short: cmdAnsibleDesc,
	Long:  fmt.Sprintf("%s\n  %s", cmdAnsibleDesc, cmdAnsibleFreeArgsDesc),
}

var ansiblePullCmd = &cobra.Command{
	Use:     cmdAnsiblePull,
	Short:   cmdAnsiblePullDesc,
	Aliases: []string{"p"},
	Run: func(cmd *cobra.Command, args []string) {
		err := RunAnsiblePull()
		if err != nil {
			klog.Errorf("error: %s", err)
			klog.Fatalf(cmdFailureStatus, cmdAnsibleError)
		}
	},
}

func NewAnsibleDeploySubCommand() *cobra.Command {
	var toolchainUpdate bool
	var deployPlaybook string
	var deployUpgrade bool
	var deployCheck bool
	var deployBootstrap bool
	var deployListTags bool
	var deployTags string
	var deploySkipTags string
	var deployLimit string
	var deployExtraVars string
	var deployVerbose bool
	var deploySkip bool

	sub := &cobra.Command{
		Use:   cmdAnsibleDeploy,
		Short: cmdAnsibleDeployDesc,
		Run: func(cmd *cobra.Command, args []string) {
			err := RunAnsible(toolchainUpdate, deployPlaybook, deployUpgrade, deployCheck, deployBootstrap, deployListTags, deployTags, deploySkipTags, deployExtraVars, deployLimit, deployVerbose, deploySkip, args)
			if err != nil {
				klog.Errorf("error: %s", err)
				klog.Fatalf(cmdFailureStatus, cmdAnsibleError)
			}
		},
	}

	sub.Flags().StringVarP(&deployPlaybook, "playbook", "p", "", cmdAnsibleDeployPlaybookDesc)
	err := sub.MarkFlagRequired("playbook")
	if err != nil {
		klog.Error(err)
	}
	err = sub.MarkFlagFilename("playbook", "yml")
	if err != nil {
		klog.Error(err)
	}

	sub.Flags().BoolVarP(&toolchainUpdate, "update-toolchain", "", false, cmdToolchainUpdateDesc)
	sub.Flags().BoolVarP(&deployUpgrade, "upgrade", "u", false, cmdAnsibleDeployUpgradeDesc)
	sub.Flags().BoolVarP(&deployCheck, "check", "c", false, cmdAnsibleDeployCheckDesc)
	sub.Flags().BoolVarP(&deployBootstrap, "bootstrap", "b", false, cmdAnsibleDeployBootstrapDesc)
	sub.Flags().BoolVarP(&deployListTags, "list-tags", "l", false, cmdAnsibleDeployListTagsDesc)
	sub.Flags().StringVarP(&deployTags, "tags", "t", "", cmdAnsibleDeployTagsDesc)
	sub.Flags().StringVarP(&deploySkipTags, "skip-tags", "S", "", cmdAnsibleDeploySkipTagsDesc)
	sub.Flags().StringVarP(&deployExtraVars, "extra-vars", "E", "", cmdAnsibleDeployExtraVarsDesc)
	sub.Flags().StringVarP(&deployLimit, "limit", "L", "", cmdAnsibleDeployLimitDesc)
	sub.Flags().BoolVarP(&deployVerbose, "verbose", "v", false, cmdAnsibleDeployVerboseDesc)
	sub.Flags().BoolVarP(&deploySkip, "skip", "s", false, cmdAnsibleDeploySkipDesc)

	return sub
}

var ansibleInventorySubCommands = map[string]string{
	cmdAnsibleInventoryActionGraph: "Create inventory graph",
	cmdAnsibleInventoryActionHost:  "Output specific host info, works as inventory script",
	cmdAnsibleInventoryActionList:  "Output all hosts info, works as inventory script",
}

var ansibleInventoryCmd = &cobra.Command{
	Use:   cmdAnsibleInventory,
	Short: cmdAnsibleInventoryDesc,
}

func NewAnsibleInventorySubCommand(name, desc string) *cobra.Command {
	var toolchainUpdate bool
	var ivPlaybook string
	var ivGroup string
	var ivHost string
	var ivOutput string
	var ivLimit string
	var ivExtraVars string
	var ivVerbose bool

	sub := &cobra.Command{
		Use:   name,
		Short: desc,
		Long:  fmt.Sprintf("%s\n  %s", desc, cmdAnsibleFreeArgsDesc),
		Run: func(cmd *cobra.Command, args []string) {
			err := RunAnsibleInventory(toolchainUpdate, name, ivPlaybook, ivGroup, ivHost, ivOutput, ivExtraVars, ivLimit, ivVerbose, args)
			if err != nil {
				klog.Errorf("error: %s", err)
				klog.Fatalf(cmdFailureStatus, cmdAnsibleError)
			}
		},
	}

	sub.Flags().BoolVarP(&toolchainUpdate, "update-toolchain", "", false, cmdToolchainUpdateDesc)
	sub.Flags().StringVarP(&ivPlaybook, "playbook", "p", "", cmdAnsibleInventoryPlaybookDesc)
	sub.Flags().StringVarP(&ivExtraVars, "extra-vars", "e", "", cmdAnsibleInventoryExtraVarsDesc)
	sub.Flags().BoolVarP(&ivVerbose, "verbose", "v", false, cmdAnsibleInventoryVerboseDesc)

	if name == cmdAnsibleInventoryActionGraph {
		sub.Flags().StringVarP(&ivGroup, "group", "g", "", cmdAnsibleInventoryGroupDesc)
		sub.Flags().StringVarP(&ivLimit, "limit", "l", "", cmdAnsibleInventoryLimitDesc)
	}

	if name == cmdAnsibleInventoryActionHost {
		sub.Flags().StringVarP(&ivHost, "host", "H", "", cmdAnsibleInventoryHostDesc)
		err := sub.MarkFlagRequired("host")
		if err != nil {
			klog.Error(err)
		}
	}

	if name == cmdAnsibleInventoryActionList {
		sub.Flags().StringVarP(&ivOutput, "output-file", "o", "", cmdAnsibleInventoryOutputDesc)
	}

	return sub
}

func init() {
	ansibleCmd.AddCommand(ansiblePullCmd)
	ansibleCmd.AddCommand(NewAnsibleDeploySubCommand())
	for sub, desc := range ansibleInventorySubCommands {
		ansibleInventoryCmd.AddCommand(NewAnsibleInventorySubCommand(sub, desc))
	}
	ansibleCmd.AddCommand(ansibleInventoryCmd)
	RootCmd.AddCommand(ansibleCmd)
}
