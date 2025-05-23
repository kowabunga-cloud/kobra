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

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
	"gopkg.in/yaml.v3"
)

// PlatformConfig is the root definition of a managed platform
type PlatformConfig struct {
	Secrets PlatformConfigSecrets `yaml:"secrets"`
	TF      PlatformConfigTF      `yaml:"tf,omitempty"`
}

// PlatformConfigSecrets contains secrets-specific configuration
type PlatformConfigSecrets struct {
	Provider    string                    `yaml:"provider"`
	MasterKeyID string                    `yaml:"master_key_id"`
	AWS         PlatformConfigSecretsAWS  `yaml:"aws,omitempty"`
	Env         PlatformConfigSecretsEnv  `yaml:"env,omitempty"`
	File        PlatformConfigSecretsFile `yaml:"file,omitempty"`
	HCP         PlatformConfigSecretsHCP  `yaml:"hcp,omitempty"`
}

// PlatformConfigSecretsAWS contains AWS Secrets Manager secrets-specific configuration
type PlatformConfigSecretsAWS struct {
	Region  string `yaml:"region"`
	ID      string `yaml:"id"`
	RoleARN string `yaml:"role_arn"`
}

// PlatformConfigSecretsEnv contains environment variable secrets-specific configuration
type PlatformConfigSecretsEnv struct {
	Var string `yaml:"var,omitempty"`
}

// PlatformConfigSecretsFile contains file-based secrets-specific configuration
type PlatformConfigSecretsFile struct {
	Path string `yaml:"path"`
}

// PlatformConfigSecretsHCP contains Hashicorp Vault secrets-specific configuration
type PlatformConfigSecretsHCP struct {
	Endpoint string `yaml:"endpoint,omitempty"`
}

// PlatformConfigTF contains tf-specific configuration
type PlatformConfigTF struct {
	Provider  string `yaml:"provider,omitempty"`
	Version   string `yaml:"version,omitempty"`
	UseSystem bool   `yaml:"use_system,omitempty"`
}

const (
	PlatformConfigFile = "kobra.yml"
	InvalidConfigField = "empty or invalid %s in platform configuration file: '%s'"

	SecretsProviderAWS     = "aws"
	SecretsProviderEnv     = "env"
	SecretsProviderFile    = "file"
	SecretsProviderHCP     = "hcp"
	SecretsProviderInput   = "input"
	SecretsProviderKeyring = "keyring"

	ToolchainVersionLatest = "latest"

	TfProviderOpenTofu  = "opentofu"
	TfProviderTerraform = "terraform"
)

func isSupportedSecretsProvider(provider string) bool {
	switch provider {
	case
		SecretsProviderAWS,
		SecretsProviderEnv,
		SecretsProviderFile,
		SecretsProviderHCP,
		SecretsProviderInput,
		SecretsProviderKeyring:
		return true
	}
	return false
}

func isSupportedTfProvider(t string) bool {
	switch t {
	case
		TfProviderOpenTofu,
		TfProviderTerraform:
		return true
	}
	return false
}

func (p *PlatformConfig) IsValid() error {
	err := false
	type configValidateFunc func(string) bool
	type configParam struct {
		key     string
		f       configValidateFunc
		comment string
	}

	params := []configParam{
		configParam{p.Secrets.Provider, isSupportedSecretsProvider, "secrets provider"},
		configParam{p.TF.Provider, isSupportedTfProvider, "TF provider"},
	}

	for _, pr := range params {
		if !pr.f(pr.key) {
			klog.Warningf(InvalidConfigField, pr.comment, pr.key)
			err = true
		}
	}

	if err {
		return fmt.Errorf("invalid value")
	}

	return nil
}

func GetPlatformConfigFile() string {
	ptfDir, err := LookupPlatformDir()
	if err != nil {
		klog.Fatalf("can't find platform directory")
	}

	return fmt.Sprintf("%s/%s", ptfDir, PlatformConfigFile)
}

func GetPlatformConfig() (*PlatformConfig, error) {
	var cfg PlatformConfig

	f, err := os.Open(GetPlatformConfigFile())
	if err != nil {
		errS := fmt.Errorf("platform_configuration: file (%s) does not exist", PlatformConfigFile)
		return nil, errS
	}
	defer func() {
		_ = f.Close()
	}()

	contents, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	// unmarshal configuration
	err = yaml.Unmarshal(contents, &cfg)
	if err != nil {
		e := fmt.Errorf("platform_configuration: unable to unmarshal config (%s)", err)
		klog.Error(e)
		return nil, e
	}

	// set default value
	LookupDefault(&cfg.TF.Provider, "TF Provider", TfProviderOpenTofu)
	LookupDefault(&cfg.TF.Version, "TF Version", ToolchainVersionLatest)

	// check for valid configuration
	err = cfg.IsValid()
	if err != nil {
		e := fmt.Errorf("platform_configuration: file seems to be invalid and with unsupported keys/values (%s)", err)
		klog.Error(e)
		return nil, e
	}

	return &cfg, nil
}
