/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPlatformConfig_IsValid(t *testing.T) {
	tests := []struct {
		name      string
		config    *PlatformConfig
		expectErr bool
	}{
		{
			name: "valid configuration",
			config: &PlatformConfig{
				Git: PlatformConfigGit{
					Method: GitMethodSSH,
				},
				Secrets: PlatformConfigSecrets{
					Provider: SecretsProviderFile,
				},
				Toolchain: PlatformConfigToolchain{
					TF: PlatformConfigToolchainTF{
						Provider: TfProviderOpenTofu,
					},
				},
			},
			expectErr: false,
		},
		{
			name: "invalid git method",
			config: &PlatformConfig{
				Git: PlatformConfigGit{
					Method: "invalid_method",
				},
				Secrets: PlatformConfigSecrets{
					Provider: SecretsProviderFile,
				},
				Toolchain: PlatformConfigToolchain{
					TF: PlatformConfigToolchainTF{
						Provider: TfProviderOpenTofu,
					},
				},
			},
			expectErr: true,
		},
		{
			name: "invalid secrets provider",
			config: &PlatformConfig{
				Git: PlatformConfigGit{
					Method: GitMethodSSH,
				},
				Secrets: PlatformConfigSecrets{
					Provider: "invalid_provider",
				},
				Toolchain: PlatformConfigToolchain{
					TF: PlatformConfigToolchainTF{
						Provider: TfProviderOpenTofu,
					},
				},
			},
			expectErr: true,
		},
		{
			name: "invalid tf provider",
			config: &PlatformConfig{
				Git: PlatformConfigGit{
					Method: GitMethodSSH,
				},
				Secrets: PlatformConfigSecrets{
					Provider: SecretsProviderFile,
				},
				Toolchain: PlatformConfigToolchain{
					TF: PlatformConfigToolchainTF{
						Provider: "invalid_provider",
					},
				},
			},
			expectErr: true,
		},
		{
			name: "valid with empty git method",
			config: &PlatformConfig{
				Git: PlatformConfigGit{
					Method: GitMethodUnknown,
				},
				Secrets: PlatformConfigSecrets{
					Provider: SecretsProviderEnv,
				},
				Toolchain: PlatformConfigToolchain{
					TF: PlatformConfigToolchainTF{
						Provider: TfProviderTerraform,
					},
				},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.IsValid()
			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestGetPlatformConfig(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()

	// Create platform structure
	platformRoot := filepath.Join(tmpDir, "test_platform")
	ansibleDir := filepath.Join(platformRoot, AnsibleDirName)
	err := os.MkdirAll(ansibleDir, 0755)
	if err != nil {
		t.Fatalf("failed to create ansible dir: %v", err)
	}

	_ = os.Chdir(platformRoot)

	tests := []struct {
		name      string
		config    *PlatformConfig
		expectErr bool
	}{
		{
			name: "valid config",
			config: &PlatformConfig{
				Git: PlatformConfigGit{
					Method: GitMethodSSH,
				},
				Secrets: PlatformConfigSecrets{
					Provider:    SecretsProviderFile,
					MasterKeyID: "test-key-id",
				},
				Toolchain: PlatformConfigToolchain{
					TF: PlatformConfigToolchainTF{
						Provider: TfProviderOpenTofu,
						Version:  "1.0.0",
					},
				},
			},
			expectErr: false,
		},
		{
			name: "config with defaults",
			config: &PlatformConfig{
				Secrets: PlatformConfigSecrets{
					Provider: SecretsProviderEnv,
				},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write config file
			configFile := filepath.Join(platformRoot, PlatformConfigFile)
			data, err := yaml.Marshal(tt.config)
			if err != nil {
				t.Fatalf("failed to marshal config: %v", err)
			}

			err = os.WriteFile(configFile, data, 0644)
			if err != nil {
				t.Fatalf("failed to write config file: %v", err)
			}

			// Test GetPlatformConfig
			cfg, err := GetPlatformConfig()
			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if cfg == nil {
					t.Error("expected config, got nil")
				} else {
					// Verify defaults are set
					if cfg.Toolchain.TF.Provider == "" {
						t.Error("expected default TF provider to be set")
					}
					if cfg.Toolchain.TF.Version == "" {
						t.Error("expected default TF version to be set")
					}
				}
			}

			// Clean up
			_ = os.Remove(configFile)
		})
	}
}

func TestGetPlatformConfig_NoFile(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()

	// Create platform structure without config file
	platformRoot := filepath.Join(tmpDir, "test_platform")
	ansibleDir := filepath.Join(platformRoot, AnsibleDirName)
	err := os.MkdirAll(ansibleDir, 0755)
	if err != nil {
		t.Fatalf("failed to create ansible dir: %v", err)
	}

	_ = os.Chdir(platformRoot)

	_, err = GetPlatformConfig()
	if err == nil {
		t.Error("expected error when config file doesn't exist, got nil")
	}
}

func TestGetPlatformConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()

	// Create platform structure
	platformRoot := filepath.Join(tmpDir, "test_platform")
	ansibleDir := filepath.Join(platformRoot, AnsibleDirName)
	err := os.MkdirAll(ansibleDir, 0755)
	if err != nil {
		t.Fatalf("failed to create ansible dir: %v", err)
	}

	_ = os.Chdir(platformRoot)

	configFile := GetPlatformConfigFile()
	expected := filepath.Join(platformRoot, PlatformConfigFile)
	// Resolve both paths to handle symlinks
	expectedAbs, _ := filepath.EvalSymlinks(expected)
	configFileAbs, _ := filepath.EvalSymlinks(configFile)
	if configFileAbs != expectedAbs {
		t.Errorf("expected %q, got %q", expectedAbs, configFileAbs)
	}
}

func TestIsSupportedGitMethod(t *testing.T) {
	tests := []struct {
		method   string
		expected bool
	}{
		{GitMethodUnknown, true},
		{GitMethodSSH, true},
		{GitMethodHTTP, true},
		{"invalid", false},
		{"ftp", false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			result := isSupportedGitMethod(tt.method)
			if result != tt.expected {
				t.Errorf("expected %v for method %q, got %v", tt.expected, tt.method, result)
			}
		})
	}
}

func TestIsSupportedSecretsProvider(t *testing.T) {
	tests := []struct {
		provider string
		expected bool
	}{
		{SecretsProviderAWS, true},
		{SecretsProviderEnv, true},
		{SecretsProviderFile, true},
		{SecretsProviderHCP, true},
		{SecretsProviderInput, true},
		{SecretsProviderKeyring, true},
		{"invalid", false},
		{"vault", false},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			result := isSupportedSecretsProvider(tt.provider)
			if result != tt.expected {
				t.Errorf("expected %v for provider %q, got %v", tt.expected, tt.provider, result)
			}
		})
	}
}

func TestIsSupportedTfProvider(t *testing.T) {
	tests := []struct {
		provider string
		expected bool
	}{
		{TfProviderOpenTofu, true},
		{TfProviderTerraform, true},
		{"invalid", false},
		{"tofu", false},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			result := isSupportedTfProvider(tt.provider)
			if result != tt.expected {
				t.Errorf("expected %v for provider %q, got %v", tt.expected, tt.provider, result)
			}
		})
	}
}

func TestPlatformConfigYAMLMarshaling(t *testing.T) {
	config := &PlatformConfig{
		Git: PlatformConfigGit{
			Method: GitMethodSSH,
			SSH: PlatformConfigGitSSH{
				User:       "git",
				PrivateKey: "/path/to/key",
			},
		},
		Secrets: PlatformConfigSecrets{
			Provider:    SecretsProviderFile,
			MasterKeyID: "test-key",
			File: PlatformConfigSecretsFile{
				Path: "/path/to/secret",
			},
		},
		SSH: PlatformConfigSSH{
			Remote: PlatformConfigSshConfig{
				User:    "admin",
				KeyFile: "/path/to/ssh/key",
			},
		},
		Toolchain: PlatformConfigToolchain{
			UseSystem: true,
			TF: PlatformConfigToolchainTF{
				Provider: TfProviderOpenTofu,
				Version:  "1.0.0",
			},
			Helm: PlatformConfigToolchainHelm{
				Version: "3.0.0",
			},
		},
	}

	// Marshal to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	// Unmarshal back
	var decoded PlatformConfig
	err = yaml.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	// Verify key fields
	if decoded.Git.Method != config.Git.Method {
		t.Errorf("expected git method %q, got %q", config.Git.Method, decoded.Git.Method)
	}
	if decoded.Secrets.Provider != config.Secrets.Provider {
		t.Errorf("expected secrets provider %q, got %q", config.Secrets.Provider, decoded.Secrets.Provider)
	}
	if decoded.Toolchain.TF.Provider != config.Toolchain.TF.Provider {
		t.Errorf("expected tf provider %q, got %q", config.Toolchain.TF.Provider, decoded.Toolchain.TF.Provider)
	}
}
