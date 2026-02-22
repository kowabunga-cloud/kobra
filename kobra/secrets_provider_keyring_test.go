/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"testing"

	"github.com/99designs/keyring"
)

func TestSecretProviderKeyring_Login(t *testing.T) {
	provider := &SecretProviderKeyring{}
	err := provider.Login()
	if err != nil {
		t.Errorf("Login should not return error, got: %v", err)
	}
}

func TestSecretProviderKeyring_PostFlight(t *testing.T) {
	provider := &SecretProviderKeyring{}
	err := provider.PostFlight()
	if err != nil {
		t.Errorf("PostFlight should not return error, got: %v", err)
	}
}

func TestSecretProviderKeyring_SetAndGet(t *testing.T) {
	// Use file backend for testing
	tmpDir := t.TempDir()
	ring, err := keyring.Open(keyring.Config{
		ServiceName:              "test-kobra",
		FileDir:                  tmpDir,
		AllowedBackends:          []keyring.BackendType{keyring.FileBackend},
		FilePasswordFunc:         keyring.FixedStringPrompt("test"),
		KeychainTrustApplication: true,
	})
	if err != nil {
		t.Skipf("keyring not available: %v", err)
	}

	provider := &SecretProviderKeyring{
		Keyring: ring,
		ID:      "test-key-id",
	}

	// Test Set
	testSecret := "test_secret_value"
	err = provider.Set(testSecret)
	if err != nil {
		t.Fatalf("unexpected error setting secret: %v", err)
	}

	// Test Get
	secret, err := provider.Get()
	if err != nil {
		t.Errorf("unexpected error getting secret: %v", err)
	}
	if secret != testSecret {
		t.Errorf("expected %q, got %q", testSecret, secret)
	}
}

func TestNewSecretProviderKeyring(t *testing.T) {
	tmpDir := t.TempDir()

	// Mock platform config
	ptfCfg := &PlatformConfig{
		Secrets: PlatformConfigSecrets{
			MasterKeyID: "test-master-key",
		},
	}

	// Try to create a keyring provider
	// This may fail on systems without keyring support, so we skip if it does
	provider, err := NewSecretProviderKeyring(ptfCfg)
	if err != nil {
		t.Skipf("keyring not available on this system: %v", err)
	}

	if provider == nil {
		t.Error("expected provider, got nil")
		return
	}
	if provider.ID != ptfCfg.Secrets.MasterKeyID {
		t.Errorf("expected ID %q, got %q", ptfCfg.Secrets.MasterKeyID, provider.ID)
	}

	_ = tmpDir // avoid unused warning
}

func TestKeyringService(t *testing.T) {
	if KeyringService != "kobra" {
		t.Errorf("expected KeyringService to be 'kobra', got %q", KeyringService)
	}
}
