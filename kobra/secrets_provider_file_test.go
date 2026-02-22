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

func TestSecretProviderFile_Get(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_secret.txt")

	tests := []struct {
		name      string
		content   string
		expectErr bool
	}{
		{
			name:      "file with content",
			content:   "test_secret_value",
			expectErr: false,
		},
		{
			name:      "empty file",
			content:   "",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := os.WriteFile(testFile, []byte(tt.content), 0600)
			if err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			provider := &SecretProviderFile{
				Filename: testFile,
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
				if secret != tt.content {
					t.Errorf("expected %q, got %q", tt.content, secret)
				}
			}

			_ = os.Remove(testFile)
		})
	}
}

func TestSecretProviderFile_Set(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_secret.txt")

	provider := &SecretProviderFile{
		Filename: testFile,
	}

	testSecret := "test_secret_value"
	err := provider.Set(testSecret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify file was created with correct content
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	if string(content) != testSecret {
		t.Errorf("expected %q, got %q", testSecret, string(content))
	}

	// Verify file permissions
	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("failed to stat file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected permissions 0600, got %o", perm)
	}
}

func TestSecretProviderFile_Login(t *testing.T) {
	provider := &SecretProviderFile{
		Filename: "test.txt",
	}

	err := provider.Login()
	if err != nil {
		t.Errorf("Login should not return error, got: %v", err)
	}
}

func TestSecretProviderFile_PostFlight(t *testing.T) {
	provider := &SecretProviderFile{
		Filename: "test.txt",
	}

	err := provider.PostFlight()
	if err != nil {
		t.Errorf("PostFlight should not return error, got: %v", err)
	}
}

func TestNewSecretProviderFile(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name      string
		ptfCfg    *PlatformConfig
		expectErr bool
	}{
		{
			name: "valid file path",
			ptfCfg: &PlatformConfig{
				Secrets: PlatformConfigSecrets{
					File: PlatformConfigSecretsFile{
						Path: filepath.Join(tmpDir, "test_secret.txt"),
					},
				},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewSecretProviderFile(tt.ptfCfg)
			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if provider == nil {
					t.Error("expected provider, got nil")
				} else {
					// Verify file was created
					_, statErr := os.Stat(provider.Filename)
					if statErr != nil {
						t.Errorf("file should have been created: %v", statErr)
					}

					// Verify file permissions
					info, statErr := os.Stat(provider.Filename)
					if statErr == nil {
						perm := info.Mode().Perm()
						if perm != 0600 {
							t.Errorf("expected permissions 0600, got %o", perm)
						}
					}
				}
			}
		})
	}
}
