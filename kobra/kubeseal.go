/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"fmt"
	"os"
)

const (
	KubesealBin = "kubeseal"
)

func kubesealRunCmd(ptfCfg *PlatformConfig, sealNamespace, sealSecret, sealLiteral string, freeArgs []string) error {
	if sealLiteral == "" {
		return fmt.Errorf("literal value to seal is required. Use --literal or -l to provide it")
	}

	args := []string{
		"--raw",
		"--controller-namespace",
		ptfCfg.Toolchain.Kubeseal.Controller.NS,
		"--controller-name",
		ptfCfg.Toolchain.Kubeseal.Controller.Name,
	}

	// define scope based on provided parameters
	scope := "cluster-wide"
	if sealNamespace != "" {
		scope = "namespace-wide"
		if sealSecret != "" {
			scope = "strict"
		}
	}
	args = append(args, "--scope")
	args = append(args, scope)

	if sealNamespace != "" {
		args = append(args, "--namespace")
		args = append(args, sealNamespace)
	}

	if sealSecret != "" {
		args = append(args, "--name")
		args = append(args, sealSecret)
	}

	sealFile, err := os.CreateTemp("", "seal_")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(sealFile.Name()) // #nosec G703
	}()

	_, err = sealFile.WriteString(sealLiteral)
	if err != nil {
		_ = sealFile.Close()
		return err
	}

	args = append(args, "--from-file")
	args = append(args, sealFile.Name())

	// add free args, if provided
	args = append(args, freeArgs...)

	kubeseal, err := LookupPlatformBinary(KubesealBin)
	if err != nil {
		return err
	}

	return BinExec(kubeseal, ".", args, []string{})
}

// echo -n test | kubeseal --raw --from-file=/dev/stdin --controller-namespace=infra --controller-name=sealed-secrets

func RunKubeseal(toolchainUpdate bool, sealNamespace, sealSecret, sealLiteral string, freeArgs []string) error {
	// read platform configuration
	ptfCfg, err := GetPlatformConfig()
	if err != nil {
		return err
	}

	// setup toolchain, if needed
	err = SetupPlatformToolchain(ptfCfg, toolchainUpdate, ToolchainToolKubeseal)
	if err != nil {
		return err
	}

	// now try to run Kubeseal
	err = kubesealRunCmd(ptfCfg, sealNamespace, sealSecret, sealLiteral, freeArgs)
	if err != nil {
		return err
	}

	return nil
}
