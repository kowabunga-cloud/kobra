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
	cmdSecrets      = "secrets"
	cmdSecretsDesc  = "Manage SOPS-encrypted secrets file"
	cmdSecretsError = "Secrets"

	cmdSecretsInit     = "init"
	cmdSecretsInitDesc = "Initialize a new SOPS private/public key pair"

	cmdSecretsEncrypt     = "encrypt"
	cmdSecretsEncryptDesc = "Encrypt an existing plain-text file with SOPS"

	cmdSecretsEdit     = "edit"
	cmdSecretsEditDesc = "Create/Update/Edit a SOPS-encrypted file"

	cmdSecretsView     = "view"
	cmdSecretsViewDesc = "Display content of a SOPS-encrypted file"

	cmdSecretsGet     = "get"
	cmdSecretsGetDesc = "Retrieve Base64-encoded SOPS master key (WARNING: sensitive data)"

	cmdSecretsSet     = "set"
	cmdSecretsSetDesc = "Set/Overwrite Base64-encoded SOPS master key (WARNING: dangerous, use it with care)"

	cmdSecretsSetMasterKeyDesc    = "Base64-encoded SOPS master key to be set"
	cmdSecretsSetNoMasterKeyError = "Unable to set secrets, no Base64-encoded provided"

	cmdSecretsMeanItDesc  = "Really perform what's been asked for"
	cmdSecretsMeanItError = "Unable to get/set secrets. Use --yes-i-really-mean-it flag if that's really what you want"
)

var secretsCmd = &cobra.Command{
	Use:   cmdSecrets,
	Short: cmdSecretsDesc,
}

var secretsInitCmd = &cobra.Command{
	Use:     cmdSecretsInit,
	Short:   cmdSecretsInitDesc,
	Aliases: []string{"i"},
	Run: func(cmd *cobra.Command, args []string) {
		cfg := GetConfig()
		err := RunSecretsInit(&cfg)
		if err != nil {
			klog.Fatalf(cmdFailureStatus, cmdSecretsError)
		}
	},
}

var secretsEncryptCmd = &cobra.Command{
	Use:     fmt.Sprintf("%s FILE", cmdSecretsEncrypt),
	Short:   cmdSecretsEncryptDesc,
	Aliases: []string{},
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := GetConfig()
		err := RunSecretsEncrypt(&cfg, args[0])
		if err != nil {
			klog.Fatalf(cmdFailureStatus, cmdSecretsError)
		}
	},
}

var secretsEditCmd = &cobra.Command{
	Use:     fmt.Sprintf("%s FILE", cmdSecretsEdit),
	Short:   cmdSecretsEditDesc,
	Aliases: []string{"e"},
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := GetConfig()
		err := RunSecretsEdit(&cfg, args[0])
		if err != nil {
			klog.Fatalf(cmdFailureStatus, cmdSecretsError)
		}
	},
}

var secretsViewCmd = &cobra.Command{
	Use:     fmt.Sprintf("%s FILE", cmdSecretsView),
	Short:   cmdSecretsViewDesc,
	Aliases: []string{"v"},
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := GetConfig()
		err := RunSecretsView(&cfg, args[0])
		if err != nil {
			klog.Errorf("error: %s", err)
			klog.Fatalf(cmdFailureStatus, cmdSecretsError)
		}
	},
}

func NewSecretsGetSetSubCommand(name, desc string) *cobra.Command {
	var iMeanIt bool
	var masterKey string

	sub := &cobra.Command{
		Use:   name,
		Short: desc,
		Run: func(cmd *cobra.Command, args []string) {
			cfg := GetConfig()

			// are you sure ?
			if !iMeanIt {
				klog.Fatalf(cmdSecretsMeanItError)
			}

			switch name {
			case cmdSecretsGet:
				err := RunSecretsGet(&cfg)
				if err != nil {
					klog.Fatalf(cmdFailureStatus, cmdSecretsError)
				}
			case cmdSecretsSet:
				if masterKey == "" {
					klog.Fatalf(cmdSecretsSetNoMasterKeyError)
				}

				err := RunSecretsSet(&cfg, masterKey)
				if err != nil {
					klog.Fatalf(cmdFailureStatus, cmdSecretsError)
				}
			}
		},
	}

	sub.Flags().BoolVarP(&iMeanIt, "yes-i-really-mean-it", "", false, cmdSecretsMeanItDesc)
	if name == cmdSecretsSet {
		sub.Flags().StringVarP(&masterKey, "master-key", "k", "", cmdSecretsSetMasterKeyDesc)
	}

	return sub
}

func init() {
	secretsCmd.AddCommand(secretsInitCmd)
	secretsCmd.AddCommand(secretsEncryptCmd)
	secretsCmd.AddCommand(secretsEditCmd)
	secretsCmd.AddCommand(secretsViewCmd)
	secretsCmd.AddCommand(NewSecretsGetSetSubCommand(cmdSecretsGet, cmdSecretsGetDesc))
	secretsCmd.AddCommand(NewSecretsGetSetSubCommand(cmdSecretsSet, cmdSecretsSetDesc))
	RootCmd.AddCommand(secretsCmd)
}
