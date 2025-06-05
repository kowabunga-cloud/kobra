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
	cmdAnsibleDeployYesDesc       = "Yes we can ! Bypass all checks and deploy nonetheless."
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
		cfg := GetConfig()
		err := RunAnsiblePull(&cfg)
		if err != nil {
			klog.Errorf("error: %s", err)
			klog.Fatalf(cmdFailureStatus, cmdAnsibleError)
		}
	},
}

func NewAnsibleDeploySubCommand() *cobra.Command {
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
	var deployYes bool

	sub := &cobra.Command{
		Use:   cmdAnsibleDeploy,
		Short: cmdAnsibleDeployDesc,
		Run: func(cmd *cobra.Command, args []string) {
			cfg := GetConfig()
			err := RunAnsible(&cfg, deployPlaybook, deployUpgrade, deployCheck, deployBootstrap, deployListTags, deployTags, deploySkipTags, deployExtraVars, deployLimit, deployVerbose, deployYes, args)
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

	sub.Flags().BoolVarP(&deployUpgrade, "upgrade", "u", false, cmdAnsibleDeployUpgradeDesc)
	sub.Flags().BoolVarP(&deployCheck, "check", "c", false, cmdAnsibleDeployCheckDesc)
	sub.Flags().BoolVarP(&deployBootstrap, "bootstrap", "b", false, cmdAnsibleDeployBootstrapDesc)
	sub.Flags().BoolVarP(&deployListTags, "list-tags", "l", false, cmdAnsibleDeployListTagsDesc)
	sub.Flags().StringVarP(&deployTags, "tags", "t", "", cmdAnsibleDeployTagsDesc)
	sub.Flags().StringVarP(&deploySkipTags, "skip-tags", "s", "", cmdAnsibleDeploySkipTagsDesc)
	sub.Flags().StringVarP(&deployExtraVars, "extra-vars", "E", "", cmdAnsibleDeployExtraVarsDesc)
	sub.Flags().StringVarP(&deployLimit, "limit", "L", "", cmdAnsibleDeployLimitDesc)
	sub.Flags().BoolVarP(&deployVerbose, "verbose", "v", false, cmdAnsibleDeployVerboseDesc)
	sub.Flags().BoolVarP(&deployYes, "yes", "y", false, cmdAnsibleDeployYesDesc)

	return sub
}

func init() {
	ansibleCmd.AddCommand(ansiblePullCmd)
	ansibleCmd.AddCommand(NewAnsibleDeploySubCommand())
	RootCmd.AddCommand(ansibleCmd)
}
