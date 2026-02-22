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

func TestExpandTilde(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
		checkFunc func(string) bool
	}{
		{
			name:      "no tilde",
			input:     "/absolute/path",
			expectErr: false,
			checkFunc: func(result string) bool {
				return result == "/absolute/path"
			},
		},
		{
			name:      "tilde with path",
			input:     "~/.ssh/config",
			expectErr: false,
			checkFunc: func(result string) bool {
				home, _ := os.UserHomeDir()
				expected := filepath.Join(home, ".ssh/config")
				return result == expected
			},
		},
		{
			name:      "relative path",
			input:     "relative/path",
			expectErr: false,
			checkFunc: func(result string) bool {
				return result == "relative/path"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := expandTilde(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if !tt.checkFunc(result) {
					t.Errorf("result check failed for input %q, got %q", tt.input, result)
				}
			}
		})
	}
}

func TestGetSSHCredentials(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test SSH key file
	testKeyFile := filepath.Join(tmpDir, "test_key")
	err := os.WriteFile(testKeyFile, []byte("test key"), 0600)
	if err != nil {
		t.Fatalf("failed to create test key file: %v", err)
	}

	tests := []struct {
		name         string
		ptfCfg       *PlatformConfig
		bootstrap    bool
		expectedUser string
		expectedKey  string
		expectErr    bool
	}{
		{
			name: "remote credentials",
			ptfCfg: &PlatformConfig{
				SSH: PlatformConfigSSH{
					Remote: PlatformConfigSshConfig{
						User:    "testuser",
						KeyFile: testKeyFile,
					},
				},
			},
			bootstrap:    false,
			expectedUser: "testuser",
			expectedKey:  testKeyFile,
			expectErr:    false,
		},
		{
			name: "bootstrap credentials",
			ptfCfg: &PlatformConfig{
				SSH: PlatformConfigSSH{
					Bootstrap: PlatformConfigSshConfig{
						User:    "bootstrapuser",
						KeyFile: testKeyFile,
					},
				},
			},
			bootstrap:    true,
			expectedUser: "bootstrapuser",
			expectedKey:  testKeyFile,
			expectErr:    false,
		},
		{
			name: "empty credentials",
			ptfCfg: &PlatformConfig{
				SSH: PlatformConfigSSH{},
			},
			bootstrap:    false,
			expectedUser: "",
			expectedKey:  "",
			expectErr:    false,
		},
		{
			name: "non-existent key file",
			ptfCfg: &PlatformConfig{
				SSH: PlatformConfigSSH{
					Remote: PlatformConfigSshConfig{
						User:    "testuser",
						KeyFile: "/nonexistent/key",
					},
				},
			},
			bootstrap:    false,
			expectedUser: "testuser",
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, key, err := GetSSHCredentials(tt.ptfCfg, tt.bootstrap)
			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if user != tt.expectedUser {
					t.Errorf("expected user %q, got %q", tt.expectedUser, user)
				}
				if key != tt.expectedKey {
					t.Errorf("expected key %q, got %q", tt.expectedKey, key)
				}
			}
		})
	}
}

func TestGetSSHCredentials_TildeExpansion(t *testing.T) {
	tmpDir := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("can't get home directory: %v", err)
	}

	// Create a test SSH directory and key in home
	sshDir := filepath.Join(home, ".ssh_test_kobra")
	err = os.MkdirAll(sshDir, 0700)
	if err != nil {
		t.Fatalf("failed to create ssh dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(sshDir) }()

	testKeyFile := filepath.Join(sshDir, "test_key")
	err = os.WriteFile(testKeyFile, []byte("test key"), 0600)
	if err != nil {
		t.Fatalf("failed to create test key file: %v", err)
	}

	ptfCfg := &PlatformConfig{
		SSH: PlatformConfigSSH{
			Remote: PlatformConfigSshConfig{
				User:    "testuser",
				KeyFile: "~/.ssh_test_kobra/test_key",
			},
		},
	}

	user, key, err := GetSSHCredentials(ptfCfg, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user != "testuser" {
		t.Errorf("expected user 'testuser', got %q", user)
	}
	if key != testKeyFile {
		t.Errorf("expected key %q, got %q", testKeyFile, key)
	}

	_ = tmpDir // avoid unused warning
}

func TestSSHConstants(t *testing.T) {
	if SSHConfigUser != "user" {
		t.Errorf("expected SSHConfigUser to be 'user', got %q", SSHConfigUser)
	}
	if SSHConfigKey != "IdentityFile" {
		t.Errorf("expected SSHConfigKey to be 'IdentityFile', got %q", SSHConfigKey)
	}
	if SSHAgentSocketEnv != "SSH_AUTH_SOCK" {
		t.Errorf("expected SSHAgentSocketEnv to be 'SSH_AUTH_SOCK', got %q", SSHAgentSocketEnv)
	}
}
