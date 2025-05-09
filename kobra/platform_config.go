/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"fmt"

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
	"gopkg.in/yaml.v3"
)

// PlatformConfig is the root definition of a managed platform
type PlatformConfig struct {
	Secrets PlatformConfigSecrets `yaml:"secrets"`
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
type PlatformConfigSecretsHCP struct{}

const (
	PlatformConfigFile = "kobra.yml"
	InvalidConfigField = "%s: empty or invalid %s in platform configuration file: '%s'"

	SecretsProviderAWS   = "aws"
	SecretsProviderEnv   = "env"
	SecretsProviderFile  = "file"
	SecretsProviderHCP   = "hcp"
	SecretsProviderInput = "input"
)

func isSupportedSecretsProvider(provider string) bool {
	switch provider {
	case
		SecretsProviderAWS,
		SecretsProviderEnv,
		SecretsProviderFile,
		SecretsProviderHCP,
		SecretsProviderInput:
		return true
	}
	return false
}

func (p *PlatformConfig) IsValid(ptf string) error {

	err := false
	type configValidateFunc func(string) bool
	type configParam struct {
		key     string
		f       configValidateFunc
		comment string
	}

	params := []configParam{
		configParam{p.Secrets.Provider, isSupportedSecretsProvider, "secrets provider"},
	}

	for _, pr := range params {
		if !pr.f(pr.key) {
			klog.Warningf(InvalidConfigField, ptf, pr.comment, pr.key)
			err = true
		}
	}

	if err {
		return fmt.Errorf("invalid value")
	}

	return nil
}

func GetPlatformConfig(ptf string, contents []byte) (PlatformConfig, error) {
	var cfg PlatformConfig

	// unmarshal configuration
	err := yaml.Unmarshal(contents, &cfg)
	if err != nil {
		e := fmt.Errorf("%s platform_configuration: unable to unmarshal config (%s)", ptf, err)
		klog.Error(e)
		return cfg, e
	}

	// check for valid configuration
	err = cfg.IsValid(ptf)
	if err != nil {
		klog.Errorf("%s: platform configuration file seems to be invalid and with unsupported keys/values (%s)", ptf, err)
	}

	return cfg, nil
}
