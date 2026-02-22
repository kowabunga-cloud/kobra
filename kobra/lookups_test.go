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
)

func TestLookupDefault(t *testing.T) {
	tests := []struct {
		name     string
		cfg      string
		v        string
		dft      string
		expected string
		changed  bool
	}{
		{
			name:     "empty config uses default",
			cfg:      "",
			v:        "TEST_VAR",
			dft:      "default_value",
			expected: "default_value",
			changed:  true,
		},
		{
			name:     "existing config unchanged",
			cfg:      "existing_value",
			v:        "TEST_VAR",
			dft:      "default_value",
			expected: "existing_value",
			changed:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			changed := LookupDefault(&cfg, tt.v, tt.dft)
			if cfg != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, cfg)
			}
			if changed != tt.changed {
				t.Errorf("expected changed=%v, got %v", tt.changed, changed)
			}
		})
	}
}

func TestLookupBooleanDefault(t *testing.T) {
	tests := []struct {
		name     string
		cfg      bool
		v        string
		dft      bool
		expected bool
		changed  bool
	}{
		{
			name:     "false config uses default true",
			cfg:      false,
			v:        "TEST_VAR",
			dft:      true,
			expected: true,
			changed:  true,
		},
		{
			name:     "false config uses default false",
			cfg:      false,
			v:        "TEST_VAR",
			dft:      false,
			expected: false,
			changed:  true,
		},
		{
			name:     "true config unchanged",
			cfg:      true,
			v:        "TEST_VAR",
			dft:      false,
			expected: true,
			changed:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			changed := LookupBooleanDefault(&cfg, tt.v, tt.dft)
			if cfg != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, cfg)
			}
			if changed != tt.changed {
				t.Errorf("expected changed=%v, got %v", tt.changed, changed)
			}
		})
	}
}

func TestLookupEnv(t *testing.T) {
	tests := []struct {
		name     string
		cfg      string
		env      string
		envValue string
		dft      string
		expected string
		changed  bool
	}{
		{
			name:     "empty config with env set",
			cfg:      "",
			env:      "TEST_ENV_VAR",
			envValue: "env_value",
			dft:      "default_value",
			expected: "env_value",
			changed:  true,
		},
		{
			name:     "empty config with env unset uses default",
			cfg:      "",
			env:      "TEST_ENV_VAR_UNSET",
			envValue: "",
			dft:      "default_value",
			expected: "default_value",
			changed:  true,
		},
		{
			name:     "existing config unchanged",
			cfg:      "existing_value",
			env:      "TEST_ENV_VAR",
			envValue: "env_value",
			dft:      "default_value",
			expected: "existing_value",
			changed:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				_ = os.Setenv(tt.env, tt.envValue)
				defer func() { _ = os.Unsetenv(tt.env) }()
			}

			cfg := tt.cfg
			changed := LookupEnv(&cfg, tt.env, tt.dft)
			if cfg != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, cfg)
			}
			if changed != tt.changed {
				t.Errorf("expected changed=%v, got %v", tt.changed, changed)
			}
		})
	}
}

func TestLookupSystemBinary(t *testing.T) {
	// Test with a common system binary
	binPath, err := LookupSystemBinary("ls")
	if err != nil {
		t.Fatalf("expected to find 'ls' binary, got error: %v", err)
	}
	if binPath == "" {
		t.Error("expected non-empty path for 'ls' binary")
	}

	// Test with non-existent binary
	_, err = LookupSystemBinary("nonexistent_binary_xyz")
	if err == nil {
		t.Error("expected error for non-existent binary, got nil")
	}
}

func TestLookupPlatformDir(t *testing.T) {
	// Create a temporary directory structure
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()

	t.Run("from ansible directory", func(t *testing.T) {
		// Create ansible directory
		ansibleDir := filepath.Join(tmpDir, "test_platform", AnsibleDirName)
		err := os.MkdirAll(ansibleDir, 0755)
		if err != nil {
			t.Fatalf("failed to create ansible dir: %v", err)
		}

		// Change to ansible directory
		_ = os.Chdir(ansibleDir)
		platformDir, err := LookupPlatformDir()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := filepath.Join(tmpDir, "test_platform")
		// Resolve both paths to handle symlinks
		expectedAbs, _ := filepath.EvalSymlinks(expected)
		platformAbs, _ := filepath.EvalSymlinks(platformDir)
		if platformAbs != expectedAbs {
			t.Errorf("expected %q, got %q", expectedAbs, platformAbs)
		}
	})

	t.Run("from platform root", func(t *testing.T) {
		// Create platform root with ansible subdirectory
		platformRoot := filepath.Join(tmpDir, "test_platform2")
		ansibleDir := filepath.Join(platformRoot, AnsibleDirName)
		err := os.MkdirAll(ansibleDir, 0755)
		if err != nil {
			t.Fatalf("failed to create ansible dir: %v", err)
		}

		// Change to platform root
		_ = os.Chdir(platformRoot)
		dir, err := LookupPlatformDir()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Resolve both paths to handle symlinks
		expectedAbs, _ := filepath.EvalSymlinks(platformRoot)
		dirAbs, _ := filepath.EvalSymlinks(dir)
		if dirAbs != expectedAbs {
			t.Errorf("expected %q, got %q", expectedAbs, dirAbs)
		}
	})

	t.Run("from helmfile directory", func(t *testing.T) {
		// Create helmfile directory
		helmfileDir := filepath.Join(tmpDir, "test_platform3", HelmfileDirName)
		err := os.MkdirAll(helmfileDir, 0755)
		if err != nil {
			t.Fatalf("failed to create helmfile dir: %v", err)
		}

		// Change to helmfile directory
		_ = os.Chdir(helmfileDir)
		platformDir, err := LookupPlatformDir()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := filepath.Join(tmpDir, "test_platform3")
		// Resolve both paths to handle symlinks
		expectedAbs, _ := filepath.EvalSymlinks(expected)
		platformAbs, _ := filepath.EvalSymlinks(platformDir)
		if platformAbs != expectedAbs {
			t.Errorf("expected %q, got %q", expectedAbs, platformAbs)
		}
	})

	t.Run("from terraform directory", func(t *testing.T) {
		// Create terraform directory
		tfDir := filepath.Join(tmpDir, "test_platform4", TerraformDirName)
		err := os.MkdirAll(tfDir, 0755)
		if err != nil {
			t.Fatalf("failed to create terraform dir: %v", err)
		}

		// Change to terraform directory
		_ = os.Chdir(tfDir)
		platformDir, err := LookupPlatformDir()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := filepath.Join(tmpDir, "test_platform4")
		// Resolve both paths to handle symlinks
		expectedAbs, _ := filepath.EvalSymlinks(expected)
		platformAbs, _ := filepath.EvalSymlinks(platformDir)
		if platformAbs != expectedAbs {
			t.Errorf("expected %q, got %q", expectedAbs, platformAbs)
		}
	})
}

func TestLookupPlatformConfigDir(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()

	// Create ansible directory to establish platform root
	platformRoot := filepath.Join(tmpDir, "test_platform")
	ansibleDir := filepath.Join(platformRoot, AnsibleDirName)
	err := os.MkdirAll(ansibleDir, 0755)
	if err != nil {
		t.Fatalf("failed to create ansible dir: %v", err)
	}

	_ = os.Chdir(platformRoot)

	cfgDir, err := LookupPlatformConfigDir()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := filepath.Join(platformRoot, KobraConfigDir)
	// Resolve both paths to handle symlinks
	expectedAbs, _ := filepath.EvalSymlinks(expected)
	cfgDirAbs, _ := filepath.EvalSymlinks(cfgDir)
	if cfgDirAbs != expectedAbs {
		t.Errorf("expected %q, got %q", expectedAbs, cfgDirAbs)
	}

	// Verify directory was created
	info, err := os.Stat(cfgDir)
	if err != nil {
		t.Errorf("config directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected config path to be a directory")
	}
}

func TestLookupPlatformBinDir(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()

	// Create ansible directory to establish platform root
	platformRoot := filepath.Join(tmpDir, "test_platform")
	ansibleDir := filepath.Join(platformRoot, AnsibleDirName)
	err := os.MkdirAll(ansibleDir, 0755)
	if err != nil {
		t.Fatalf("failed to create ansible dir: %v", err)
	}

	_ = os.Chdir(platformRoot)

	binDir, err := LookupPlatformBinDir()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := filepath.Join(platformRoot, KobraConfigDir, KobraPlatformBinDir)
	// Resolve both paths to handle symlinks
	expectedAbs, _ := filepath.EvalSymlinks(expected)
	binDirAbs, _ := filepath.EvalSymlinks(binDir)
	if binDirAbs != expectedAbs {
		t.Errorf("expected %q, got %q", expectedAbs, binDirAbs)
	}

	// Verify directory was created
	info, err := os.Stat(binDir)
	if err != nil {
		t.Errorf("bin directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected bin path to be a directory")
	}
}

func TestLookupPlatformBinary(t *testing.T) {
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

	// Create a test binary file
	binDir, err := LookupPlatformBinDir()
	if err != nil {
		t.Fatalf("failed to get bin dir: %v", err)
	}

	testBinPath := filepath.Join(binDir, "testbin")
	err = os.WriteFile(testBinPath, []byte("#!/bin/sh\necho test"), 0755)
	if err != nil {
		t.Fatalf("failed to create test binary: %v", err)
	}

	// Test finding existing binary
	binPath, err := LookupPlatformBinary("testbin")
	if err != nil {
		t.Errorf("unexpected error finding binary: %v", err)
	}
	if binPath != testBinPath {
		t.Errorf("expected %q, got %q", testBinPath, binPath)
	}

	// Test non-existent binary
	_, err = LookupPlatformBinary("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent binary, got nil")
	}
}
