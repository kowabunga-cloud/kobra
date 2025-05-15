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

func LookupConfigXDir(d string) (string, error) {

	confDir, err := GetConfigDir()
	if err != nil {
		return "", KobraError("%s", err.Error())
	}

	dir := fmt.Sprintf("%s/%s", confDir, d)
	err = os.MkdirAll(dir, 0750)
	if err != nil && !os.IsExist(err) {
		return "", err
	}

	return dir, nil
}

func LookupConfigPluginsDir() (string, error) {
	return LookupConfigXDir(KobraConfigPluginsDir)
}

func LookupConfigPluginsBinDir() (string, error) {
	dir := fmt.Sprintf("%s/%s", KobraConfigPluginsDir, KobraConfigPluginsBinDir)
	return LookupConfigXDir(dir)
}

func LookupConfigPluginsManifest() (string, error) {
	pluginsDir, err := LookupConfigPluginsDir()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/%s", pluginsDir, KobraConfigPluginsManifestFile), nil
}

func LookupDefault(cfg *string, v, dft string) bool {
	if *cfg == "" {
		klog.Warningf("%s variable is not set, using default value", v)
		*cfg = dft
		return true
	}

	return false
}

func LookupBooleanDefault(cfg *bool, v string, dft bool) bool {
	if !*cfg {
		klog.Warningf("%s variable is not set, using default value", v)
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

func LookupBinary(cfg *string, bin string) bool {
	if *cfg == "" {
		path, err := exec.LookPath(bin)
		if err != nil {
			klog.Errorf("%s executable can't be found in $PATH", bin)
			return false
		}
		klog.Debugf("Found %s in $PATH, adding it to config ...", bin)
		*cfg = path
		return true
	}

	return false
}

func LookupPluginBinary(bin string) string {
	dir, err := LookupConfigPluginsDir()
	if err != nil {
		klog.Error(err)
		return ""
	}

	return fmt.Sprintf("%s/bin/%s", dir, bin)
}
