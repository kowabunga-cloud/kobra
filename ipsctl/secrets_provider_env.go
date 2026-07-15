/*
 * Copyright (c) Cinemo GmbH. All rights reserved.
 *
 * Originally licensed under the Apache License, Version 2.0
 * (see https://www.apache.org/licenses/LICENSE-2.0.txt).
 * Benjamin Zores, original author, granted Cinemo GmbH explicit rights
 * to relicense and use this work under proprietary terms.
 *
 * This file is proprietary and confidential. Unauthorized copying,
 * distribution, or use, via any medium, is strictly prohibited without
 * prior written permission from Cinemo GmbH.
 */

package ipsctl

import (
	"fmt"
	"os"
	"time"

	"github.com/kowabunga-cloud/common/klog"
)

const (
	SecretsProviderEnvVariableDefault = "IPSCTL_MASTER_KEY" // #nosec G101
)

type SecretProviderEnv struct {
	EnvVar string
}

func (s *SecretProviderEnv) IsSupported(feature string) bool {
	return false
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

func (s *SecretProviderEnv) LastMod(path, secret string) (time.Time, error) {
	return time.Time{}, nil
}

func (s *SecretProviderEnv) Read(path, secret string) (map[string]any, error) {
	return map[string]any{}, nil
}

func (s *SecretProviderEnv) Write(path, secret string, payload map[string]any) error {
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
