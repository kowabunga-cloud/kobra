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
	"os"
	"testing"
)

func TestSecretProviderEnv_Get(t *testing.T) {
	tests := []struct {
		name      string
		envVar    string
		envValue  string
		expectErr bool
	}{
		{
			name:      "env var set",
			envVar:    "TEST_SECRET_KEY",
			envValue:  "test_secret_value",
			expectErr: false,
		},
		{
			name:      "env var not set",
			envVar:    "TEST_SECRET_KEY_UNSET",
			envValue:  "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				_ = os.Setenv(tt.envVar, tt.envValue)
				defer func() { _ = os.Unsetenv(tt.envVar) }()
			}

			provider := &SecretProviderEnv{
				EnvVar: tt.envVar,
			}

			secret, err := provider.Get()
			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if secret != tt.envValue {
					t.Errorf("expected %q, got %q", tt.envValue, secret)
				}
			}
		})
	}
}

func TestSecretProviderEnv_Set(t *testing.T) {
	provider := &SecretProviderEnv{
		EnvVar: "TEST_SECRET",
	}

	// Set should not return error (it just prints instructions)
	err := provider.Set("test_secret_value")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSecretProviderEnv_Login(t *testing.T) {
	provider := &SecretProviderEnv{
		EnvVar: "TEST_SECRET",
	}

	err := provider.Login()
	if err != nil {
		t.Errorf("Login should not return error, got: %v", err)
	}
}

func TestSecretProviderEnv_PostFlight(t *testing.T) {
	provider := &SecretProviderEnv{
		EnvVar: "TEST_SECRET",
	}

	err := provider.PostFlight()
	if err != nil {
		t.Errorf("PostFlight should not return error, got: %v", err)
	}
}

func TestNewSecretProviderEnv(t *testing.T) {
	tests := []struct {
		name        string
		ptfCfg      *PlatformConfig
		expectedVar string
	}{
		{
			name: "custom env var",
			ptfCfg: &PlatformConfig{
				Secrets: PlatformConfigSecrets{
					Env: PlatformConfigSecretsEnv{
						Var: "CUSTOM_VAR",
					},
				},
			},
			expectedVar: "CUSTOM_VAR",
		},
		{
			name: "default env var",
			ptfCfg: &PlatformConfig{
				Secrets: PlatformConfigSecrets{
					Env: PlatformConfigSecretsEnv{
						Var: "",
					},
				},
			},
			expectedVar: SecretsProviderEnvVariableDefault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewSecretProviderEnv(tt.ptfCfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if provider.EnvVar != tt.expectedVar {
				t.Errorf("expected EnvVar %q, got %q", tt.expectedVar, provider.EnvVar)
			}
		})
	}
}
