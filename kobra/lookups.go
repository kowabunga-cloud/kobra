/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
)

const (
	KobraPlatformBinDir = "bin"

	AnsibleDirName   = "ansible"
	HelmfileDirName  = "helmfile"
	TerraformDirName = "terraform"
)

func LookupPlatformDir() (string, error) {
	// where are we ?
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// if there's an 'ansible' sub-directory, we're already at platform's root
	ansibleDir := fmt.Sprintf("%s/%s", wd, AnsibleDirName)
	_, err = os.Stat(ansibleDir)
	if err == nil {
		return wd, nil
	}

	// if we're in 'ansible' directory, then platform's root is one level down
	if filepath.Base(wd) == AnsibleDirName {
		return filepath.Dir(wd), nil
	}

	// if there's an 'helmfile' sub-directory, we're already at platform's root
	helmfileDir := fmt.Sprintf("%s/%s", wd, HelmfileDirName)
	_, err = os.Stat(helmfileDir)
	if err == nil {
		return wd, nil
	}

	// if we're in 'helmfile' directory, then platform's root is one level down
	if filepath.Base(wd) == HelmfileDirName {
		return filepath.Dir(wd), nil
	}

	// if there's an 'terraform' sub-directory, we're already at platform's root
	tfDir := fmt.Sprintf("%s/%s", wd, TerraformDirName)
	_, err = os.Stat(tfDir)
	if err == nil {
		return wd, nil
	}

	// if we're in 'terraform' directory, then platform's root is one level down
	if filepath.Base(wd) == TerraformDirName {
		return filepath.Dir(wd), nil
	}

	// lastly, we may be in a 'terraform' subdirectory, then platform's root is several levels down
	if strings.Contains(filepath.Dir(wd), TerraformDirName) {
		// let's walkthrough until we find the right 'terraform' directory
		upper := filepath.Dir(wd)
		for {
			// if we're in 'terraform' directory, then platform's root is one level down
			if filepath.Base(upper) == TerraformDirName {
				return filepath.Dir(upper), nil
			}
			// go deeper ...
			upper = filepath.Clean(upper + "/..")
		}
	}

	// everything else failed, use current directory
	return wd, nil
}

func LookupPlatformConfigDir() (string, error) {
	ptfDir, err := LookupPlatformDir()
	if err != nil {
		return "", KobraError("%s", err.Error())
	}

	cfgDir := fmt.Sprintf("%s/%s", ptfDir, KobraConfigDir)
	err = os.MkdirAll(cfgDir, 0750)
	if err != nil && !os.IsExist(err) {
		return "", err
	}

	return cfgDir, nil
}

func LookupPlatformBinDir() (string, error) {
	ptfDir, err := LookupPlatformDir()
	if err != nil {
		return "", KobraError("%s", err.Error())
	}

	cfgDir := fmt.Sprintf("%s/%s", ptfDir, KobraConfigDir)
	err = os.MkdirAll(cfgDir, 0750)
	if err != nil && !os.IsExist(err) {
		return "", err
	}

	binDir := fmt.Sprintf("%s/%s", cfgDir, KobraPlatformBinDir)
	err = os.MkdirAll(binDir, 0750)
	if err != nil && !os.IsExist(err) {
		return "", err
	}

	return binDir, nil
}

func LookupAnsibleDir() (string, error) {
	var ansibleDir string

	ptfDir, err := LookupPlatformDir()
	if err != nil {
		return ansibleDir, err
	}

	// where are we again ?
	wd, err := os.Getwd()
	if err != nil {
		return ansibleDir, err
	}

	// we're already in 'ansible' subdirectory
	if strings.Contains(filepath.Dir(wd), AnsibleDirName) && filepath.Base(wd) != AnsibleDirName {
		return wd, nil
	}

	// otherwise, let's use default path
	return fmt.Sprintf("%s/%s", ptfDir, AnsibleDirName), nil
}

func LookupHelmfileDir() (string, error) {
	var hfDir string

	ptfDir, err := LookupPlatformDir()
	if err != nil {
		return hfDir, err
	}

	// where are we again ?
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// we're already in 'helmfile' subdirectory
	if strings.Contains(filepath.Dir(wd), HelmfileDirName) && filepath.Base(wd) != HelmfileDirName {
		return wd, nil
	}

	// otherwise, let's use default path
	return fmt.Sprintf("%s/%s", ptfDir, HelmfileDirName), nil
}

func LookupTerraformDir() (string, error) {
	ptfDir, err := LookupPlatformDir()
	if err != nil {
		return "", err
	}

	// where are we again ?
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// we're already in 'terraform' subdirectory
	if strings.Contains(filepath.Dir(wd), TerraformDirName) && filepath.Base(wd) != TerraformDirName {
		return wd, nil
	}

	// otherwise, let's use default path
	return fmt.Sprintf("%s/%s", ptfDir, TerraformDirName), nil
}

func LookupDefault(cfg *string, v, dft string) bool {
	if *cfg == "" {
		klog.Debugf("%s variable is not set, using default value", v)
		*cfg = dft
		return true
	}

	return false
}

func LookupBooleanDefault(cfg *bool, v string, dft bool) bool {
	if !*cfg {
		klog.Debugf("%s variable is not set, using default value", v)
		*cfg = dft
		return true
	}

	return false
}

func LookupEnv(cfg *string, env, dft string) bool {
	if *cfg == "" {
		e := os.Getenv(env)
		if e == "" {
			klog.Errorf("%s environment variable can't be found, using default value", env)
			e = dft
		}
		klog.Debugf("Found %s environment variable, adding it to config ...", env)
		*cfg = e
		return true
	}

	return false
}

func LookupSystemBinary(binName string) (string, error) {
	return exec.LookPath(binName)
}

func LookupPlatformBinary(binName string) (string, error) {
	dir, err := LookupPlatformBinDir()
	if err != nil {
		return "", err
	}

	bin := fmt.Sprintf("%s/%s", dir, binName)

	_, err = os.Stat(bin)
	if err != nil {
		return bin, err
	}

	return bin, nil
}
