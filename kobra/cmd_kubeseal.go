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
	cmdSeal             = "kubeseal"
	cmdSealDesc         = "Generate asymetric Sealed-Secrets one-way encrypted secret"
	cmdSealFreeArgsDesc = "Tips: Use -- [ARGS] to extend it with free args"
	cmdSealError        = "Seal"

	sealNamespaceDesc = "Name of the associated Kubernetes namespace. If unspecified, sealed secret scope will be cluster-wide."
	sealSecretDesc    = "Name of associated Kubernetes secret. If unspecified, sealed secret scope will be namespace-wide."
	sealLiteralDesc   = "The sensitive value you expect to be encrypted"
)

func NewSealCommand() *cobra.Command {
	var toolchainUpdate bool
	var sealNamespace string
	var sealSecret string
	var sealLiteral string

	sealCmd := &cobra.Command{
		Use:     cmdSeal,
		Short:   cmdSealDesc,
		Aliases: []string{"seal"},
		Long:    fmt.Sprintf("%s\n  %s", cmdSealDesc, cmdSealFreeArgsDesc),
		Run: func(cmd *cobra.Command, args []string) {
			err := RunKubeseal(toolchainUpdate, sealNamespace, sealSecret, sealLiteral, args)
			if err != nil {
				klog.Fatalf(cmdFailureStatus, cmdSealError)
			}
		},
	}

	sealCmd.Flags().BoolVarP(&toolchainUpdate, "update-toolchain", "", false, cmdToolchainUpdateDesc)
	sealCmd.Flags().StringVarP(&sealNamespace, "namespace", "n", "", sealNamespaceDesc)
	sealCmd.Flags().StringVarP(&sealSecret, "secret", "s", "", sealSecretDesc)
	sealCmd.Flags().StringVarP(&sealLiteral, "literal", "l", "", sealLiteralDesc)
	err := sealCmd.MarkFlagRequired("literal")
	if err != nil {
		klog.Fatalf(cmdFailureStatus, cmdSealError)
		return nil
	}

	return sealCmd
}

func init() {
	RootCmd.AddCommand(NewSealCommand())
}
