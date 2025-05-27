/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"fmt"
	"os"

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
)

const (
	TerraformBin = "terraform"
	OpenTofuBin  = "tofu"
)

func lookupTerraform(ptfCfg *PlatformConfig) (string, error) {
	binName := OpenTofuBin
	if ptfCfg.Toolchain.TF.Provider == TfProviderTerraform {
		binName = TerraformBin
	}

	if ptfCfg.Toolchain.UseSystem {
		return LookupSystemBinary(binName)
	}

	return LookupPlatformBinary(binName)
}

func executeTF(cfg *KobraConfig, ptfCfg *PlatformConfig, secrets *KobraSecretData, tfDir, cmd, module, resource, output string, auto bool, extraArgs []string) error {

	// lookup for TF binary
	tfBin, err := lookupTerraform(ptfCfg)
	if err != nil {
		return err
	}

	// set environment variables
	envs, sops, err := setSopsEnv(secrets)
	if err != nil {
		return err
	}
	if sops != "" {
		defer func() {
			_ = os.Remove(sops)
		}()
	}

	// set command-line arguments
	args := []string{
		cmd,
	}

	// init
	if cmd == cmdTfInit {
		args = append(args, "-upgrade")
	}

	// check for resource
	if resource != "" {
		target := fmt.Sprintf("-target=%s", resource)
		args = append(args, target)
	}

	// check for module
	if module != "" {
		target := fmt.Sprintf("-target=module.%s", module)
		args = append(args, target)
	}

	//check for output
	if output != "" {
		out := fmt.Sprintf("-out=%s", output)
		args = append(args, out)
	}

	// auto-approve ??
	if auto {
		args = append(args, "-auto-approve")
	}

	// append extra command-line free args
	args = append(args, extraArgs...)

	klog.Info("Running TF ...")
	return BinExec(tfBin, tfDir, args, envs)
}

func RunTF(cfg *KobraConfig, cmd, module, resource, output string, auto, bypass bool, extraArgs []string) error {
	// get Terraform dir
	tfDir, err := LookupTerraformDir()
	if err != nil {
		return err
	}

	// read platform configuration
	ptfCfg, err := GetPlatformConfig()
	if err != nil {
		return KobraError("%s", err.Error())
	}

	// setup toolchain, if needed
	err = SetupPlatformToolchain(ptfCfg, "tf")
	if err != nil {
		return KobraError("%s", err.Error())
	}

	// get secrets
	secrets, err := GetSecrets(ptfCfg)
	if err != nil {
		return err
	}

	ready, err := IsGitRepoUpToDate(ptfCfg, bypass)
	if !ready || err != nil {
		return KobraError(GitDivergenceError)
	}

	// now try to run TF
	err = executeTF(cfg, ptfCfg, secrets, tfDir, cmd, module, resource, output, auto, extraArgs)
	if err != nil {
		return err
	}

	return nil
}
