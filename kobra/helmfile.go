/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"fmt"
	"os"
	"strings"

	"github.com/kowabunga-cloud/common/klog"
)

const (
	HelmBin                    = "helm"
	HelmfileBin                = "helmfile"
	HelmfileConfigFile         = "helmfile.yaml"
	HelmfileConfigFileTemplate = "helmfile.yaml.gotmpl"
)

func helmfileChecks(hfDir string) error {
	cfgFile := fmt.Sprintf("%s/%s", hfDir, HelmfileConfigFile)
	_, err := os.Stat(cfgFile)

	cfgFileTmpl := fmt.Sprintf("%s/%s", hfDir, HelmfileConfigFileTemplate)
	_, errTmpl := os.Stat(cfgFileTmpl)

	// ensure we have at least one proper config file
	if err != nil && errTmpl != nil {
		return KobraError("Can't find %s or %s", cfgFile, cfgFileTmpl)
	}

	return nil
}

func helmfileArgs(ptfCfg *PlatformConfig) []string {
	var helm string

	if ptfCfg.Toolchain.UseSystem {
		helm, _ = LookupSystemBinary(HelmBin)
	} else {
		helm, _ = LookupPlatformBinary(HelmBin)
	}

	args := []string{
		"--helm-binary",
		helm,
	}

	return args
}

func helmfileExec(ptfCfg *PlatformConfig, cmd, hfDir string, extraArgs, envs []string) error {
	args := []string{
		cmd,
	}
	args = append(args, helmfileArgs(ptfCfg)...)
	args = append(args, extraArgs...)

	helmfile, err := LookupPlatformBinary(HelmfileBin)
	if err != nil {
		return err
	}

	return BinExec(helmfile, hfDir, args, envs)
}

func helmfileInit(ptfCfg *PlatformConfig, hfDir string) error {
	args := []string{
		"--force",
	}
	klog.Infof("Installing Helmfile required dependencies ...")
	return helmfileExec(ptfCfg, cmdHfInit, hfDir, args, []string{})
}

func helmfileRunCmd(cmd string, ptfCfg *PlatformConfig, secrets *KobraSecretData, hfDir string, verbose bool, release, outputDir string, freeArgs []string) error {
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

	if !ptfCfg.Toolchain.UseSystem {
		path := os.Getenv("PATH")
		binDir, err := LookupPlatformBinDir()
		if err != nil {
			return err
		}

		if path != "" {
			envs = append(envs, fmt.Sprintf("PATH=%s:%s", binDir, path))
		}
	}

	args := []string{}
	if verbose {
		args = append(args, "--log-level")
		args = append(args, "debug")
	}
	if release != "" {
		args = append(args, "--selector")
		args = append(args, fmt.Sprintf("name=%s", release))
	}
	if cmd == cmdHfTemplate && outputDir != "" {
		args = append(args, "--output-dir-template")
		if strings.Contains(outputDir, "{{") {
			args = append(args, outputDir)
		} else {
			args = append(args, fmt.Sprintf("%s/{{ .Release.Namespace }}/{{ .Release.Name}}", outputDir))
		}
	}
	if cmd == cmdHfWriteVal && outputDir != "" {
		args = append(args, "--output-file-template")
		if strings.Contains(outputDir, "{{") {
			args = append(args, outputDir)
		} else {
			args = append(args, fmt.Sprintf("%s/{{ .Release.Namespace }}/{{ .Release.Name}}/values.yaml", outputDir))
		}
	}

	args = append(args, freeArgs...)

	klog.Infof("Applying Helm charts configuration ...")
	return helmfileExec(ptfCfg, cmd, hfDir, args, envs)
}

func RunHelmfile(toolchainUpdate bool, cmd string, verbose, bypass bool, release, outputDir string, freeArgs []string) error {
	// get Helmfile dir
	hfDir, err := LookupHelmfileDir()
	if err != nil {
		return err
	}

	// read platform configuration
	ptfCfg, err := GetPlatformConfig()
	if err != nil {
		return err
	}

	// setup toolchain, if needed
	err = SetupPlatformToolchain(ptfCfg, toolchainUpdate, ToolchainToolHelm, ToolchainToolHelmfile, ToolchainToolKubeseal)
	if err != nil {
		return err
	}

	// ensure we're in the right place
	err = helmfileChecks(hfDir)
	if err != nil {
		return err
	}

	// get secrets
	secrets, err := GetSecrets(ptfCfg)
	if err != nil {
		return err
	}

	ready, err := IsGitRepoUpToDate(ptfCfg, bypass)
	if !ready || err != nil {
		return err
	}

	// install/upgrade dependencies
	err = helmfileInit(ptfCfg, hfDir)
	if err != nil {
		return err
	}

	// now try to run Helmfile
	err = helmfileRunCmd(cmd, ptfCfg, secrets, hfDir, verbose, release, outputDir, freeArgs)
	if err != nil {
		return err
	}

	return nil
}
