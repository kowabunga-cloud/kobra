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
	SecretsProviderEnvVariableDefault = "KOBRA_MASTER_KEY"
)

type SecretProviderEnv struct {
	EnvVar string
}

func (s *SecretProviderEnv) Login() error {
	return nil
}

func (s *SecretProviderEnv) PostFlight() error {
	return nil
}

func (s *SecretProviderEnv) Get() (string, error) {
	val, ok := os.LookupEnv(s.EnvVar)
	if !ok {
		return "", fmt.Errorf("unset %s secret environment variable", s.EnvVar)
	}

	return val, nil
}

func (s *SecretProviderEnv) Set(secret string) error {
	klog.Infof("Please ensure to set the following environment variable into your shell's configuration:")
	klog.Infof("  export %s=%s", s.EnvVar, secret)
	return nil
}

func NewSecretProviderEnv(ptfCfg *PlatformConfig) (*SecretProviderEnv, error) {
	v := ptfCfg.Secrets.Env.Var
	if v == "" {
		v = SecretsProviderEnvVariableDefault
	}
	return &SecretProviderEnv{
		EnvVar: v,
	}, nil
}
