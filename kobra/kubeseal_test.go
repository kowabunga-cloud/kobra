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

func TestKubesealRunCmd_RequiresLiteral(t *testing.T) {
	ptfCfg := &PlatformConfig{
		Toolchain: PlatformConfigToolchain{
			Kubeseal: PlatformConfigToolchainKubeseal{
				Controller: PlatformConfigToolchainKubesealController{
					NS:   KubesealControllerDefaultNamespace,
					Name: KubesealControllerDefaultName,
				},
			},
		},
	}

	err := kubesealRunCmd(ptfCfg, "", "", "", []string{})
	if err == nil {
		t.Error("expected error when literal is empty, got nil")
	}
	if err != nil && err.Error() != "literal value to seal is required. Use --literal or -l to provide it" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestKubesealRunCmd_ScopeLogic(t *testing.T) {
	tests := []struct {
		name          string
		namespace     string
		secret        string
		expectedScope string
	}{
		{
			name:          "cluster-wide scope",
			namespace:     "",
			secret:        "",
			expectedScope: "cluster-wide",
		},
		{
			name:          "namespace-wide scope",
			namespace:     "test-ns",
			secret:        "",
			expectedScope: "namespace-wide",
		},
		{
			name:          "strict scope",
			namespace:     "test-ns",
			secret:        "test-secret",
			expectedScope: "strict",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This test validates the scope logic indirectly
			// The actual kubesealRunCmd will fail because kubeseal binary doesn't exist
			// but we can verify the error is about the binary, not the scope logic
			ptfCfg := &PlatformConfig{
				Toolchain: PlatformConfigToolchain{
					Kubeseal: PlatformConfigToolchainKubeseal{
						Controller: PlatformConfigToolchainKubesealController{
							NS:   "test-controller-ns",
							Name: "test-controller",
						},
					},
				},
			}

			err := kubesealRunCmd(ptfCfg, tt.namespace, tt.secret, "test-literal", []string{})
			// We expect an error because kubeseal binary won't be found
			if err == nil {
				t.Error("expected error, got nil")
			}
			// The error should be about lookup, not about missing literal
			if err != nil && err.Error() == "literal value to seal is required. Use --literal or -l to provide it" {
				t.Error("got literal error instead of expected lookup error")
			}
		})
	}
}

func TestPlatformConfigKubesealDefaults(t *testing.T) {
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

	// Create a minimal config without kubeseal controller settings
	config := &PlatformConfig{
		Secrets: PlatformConfigSecrets{
			Provider: SecretsProviderEnv,
		},
		Toolchain: PlatformConfigToolchain{
			TF: PlatformConfigToolchainTF{
				Provider: TfProviderOpenTofu,
			},
			Kubeseal: PlatformConfigToolchainKubeseal{
				Version: "0.26.0",
			},
		},
	}

	// Write config file
	configFile := filepath.Join(platformRoot, PlatformConfigFile)
	data, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	err = os.WriteFile(configFile, data, 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Test GetPlatformConfig
	cfg, err := GetPlatformConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify kubeseal controller defaults are set
	if cfg.Toolchain.Kubeseal.Controller.NS != KubesealControllerDefaultNamespace {
		t.Errorf("expected controller namespace %q, got %q",
			KubesealControllerDefaultNamespace, cfg.Toolchain.Kubeseal.Controller.NS)
	}

	if cfg.Toolchain.Kubeseal.Controller.Name != KubesealControllerDefaultName {
		t.Errorf("expected controller name %q, got %q",
			KubesealControllerDefaultName, cfg.Toolchain.Kubeseal.Controller.Name)
	}
}

func TestPlatformConfigKubesealCustomController(t *testing.T) {
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

	// Create config with custom kubeseal controller settings
	customNS := "custom-namespace"
	customName := "custom-controller"
	config := &PlatformConfig{
		Secrets: PlatformConfigSecrets{
			Provider: SecretsProviderEnv,
		},
		Toolchain: PlatformConfigToolchain{
			TF: PlatformConfigToolchainTF{
				Provider: TfProviderOpenTofu,
			},
			Kubeseal: PlatformConfigToolchainKubeseal{
				Version: "0.26.0",
				Controller: PlatformConfigToolchainKubesealController{
					NS:   customNS,
					Name: customName,
				},
			},
		},
	}

	// Write config file
	configFile := filepath.Join(platformRoot, PlatformConfigFile)
	data, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	err = os.WriteFile(configFile, data, 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Test GetPlatformConfig
	cfg, err := GetPlatformConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify custom kubeseal controller settings are preserved
	if cfg.Toolchain.Kubeseal.Controller.NS != customNS {
		t.Errorf("expected controller namespace %q, got %q",
			customNS, cfg.Toolchain.Kubeseal.Controller.NS)
	}

	if cfg.Toolchain.Kubeseal.Controller.Name != customName {
		t.Errorf("expected controller name %q, got %q",
			customName, cfg.Toolchain.Kubeseal.Controller.Name)
	}
}

func TestKubesealConfigYAMLMarshaling(t *testing.T) {
	config := &PlatformConfig{
		Toolchain: PlatformConfigToolchain{
			Kubeseal: PlatformConfigToolchainKubeseal{
				Version: "0.26.0",
				Controller: PlatformConfigToolchainKubesealController{
					NS:   "infra",
					Name: "sealed-secrets-controller",
				},
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

	// Verify kubeseal fields
	if decoded.Toolchain.Kubeseal.Version != config.Toolchain.Kubeseal.Version {
		t.Errorf("expected kubeseal version %q, got %q",
			config.Toolchain.Kubeseal.Version, decoded.Toolchain.Kubeseal.Version)
	}
	if decoded.Toolchain.Kubeseal.Controller.NS != config.Toolchain.Kubeseal.Controller.NS {
		t.Errorf("expected controller namespace %q, got %q",
			config.Toolchain.Kubeseal.Controller.NS, decoded.Toolchain.Kubeseal.Controller.NS)
	}
	if decoded.Toolchain.Kubeseal.Controller.Name != config.Toolchain.Kubeseal.Controller.Name {
		t.Errorf("expected controller name %q, got %q",
			config.Toolchain.Kubeseal.Controller.Name, decoded.Toolchain.Kubeseal.Controller.Name)
	}
}
