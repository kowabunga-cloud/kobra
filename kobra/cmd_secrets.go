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
)

var secretsCmd = &cobra.Command{
	Use:   cmdSecrets,
	Short: cmdSecretsDesc,
}

var secretsInitCmd = &cobra.Command{
	Use:     cmdSecretsInit,
	Short:   cmdSecretsInitDesc,
	Aliases: []string{"i"},
	Run:     func(cmd *cobra.Command, args []string) {},
}

var secretsEncryptCmd = &cobra.Command{
	Use:     fmt.Sprintf("%s FILE", cmdSecretsEncrypt),
	Short:   cmdSecretsEncryptDesc,
	Aliases: []string{},
	Args:    cobra.ExactArgs(1),
	Run:     func(cmd *cobra.Command, args []string) {},
}

var secretsEditCmd = &cobra.Command{
	Use:     fmt.Sprintf("%s FILE", cmdSecretsEdit),
	Short:   cmdSecretsEditDesc,
	Aliases: []string{"e"},
	Args:    cobra.ExactArgs(1),
	Run:     func(cmd *cobra.Command, args []string) {},
}

var secretsViewCmd = &cobra.Command{
	Use:     fmt.Sprintf("%s FILE", cmdSecretsView),
	Short:   cmdSecretsViewDesc,
	Aliases: []string{"v"},
	Args:    cobra.ExactArgs(1),
	Run:     func(cmd *cobra.Command, args []string) {},
}

func init() {
	secretsCmd.AddCommand(secretsInitCmd)
	secretsCmd.AddCommand(secretsEncryptCmd)
	secretsCmd.AddCommand(secretsEditCmd)
	secretsCmd.AddCommand(secretsViewCmd)
	RootCmd.AddCommand(secretsCmd)
}
