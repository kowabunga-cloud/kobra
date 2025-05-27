/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
)

type KobraConfig struct {
	File string `yaml:"-"`
}

const (
	KobraConfigDir           = ".kobra.d"
	KobraConfigFile          = "config"
	KobraConfigPluginsDir    = "plugins"
	KobraConfigPluginsBinDir = "bin"

	SopsBin = "sops"
)

func (c *KobraConfig) Write(dst string) {
	file, _ := yaml.Marshal(c)
	_ = os.WriteFile(dst, file, 0600)
}

func GetConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", KobraError("%s", err.Error())
	}

	confDir := fmt.Sprintf("%s/%s", home, KobraConfigDir)
	err = os.Mkdir(confDir, 0750)
	if err != nil && !os.IsExist(err) {
		return "", err
	}

	return confDir, nil
}

func GetConfig() KobraConfig {
	var config KobraConfig

	confDir, err := GetConfigDir()
	if err != nil {
		klog.Error(err)
		os.Exit(1)
	}

	config.File = fmt.Sprintf("%s/%s", confDir, KobraConfigFile)
	cfg, err := os.Open(config.File)
	if err != nil {
		klog.Warningf("Kobra configuration file is missing, creating it ...")
	}
	defer func() {
		_ = cfg.Close()
	}()

	// unmarshal configuration
	contents, _ := io.ReadAll(cfg)
	err = yaml.Unmarshal(contents, &config)
	if err != nil {
		klog.Errorf("config: unable to unmarshal config (%s)", err)
		os.Exit(1)
	}

	return config
}
