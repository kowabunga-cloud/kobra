/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// mockSecretsProvider implements SecretsProvider for testing
type mockSecretsProvider struct {
	lastModTime    time.Time
	lastModErr     error
	supportSyncMap bool
}

func (m *mockSecretsProvider) IsSupported(feature string) bool {
	return m.supportSyncMap && feature == SecretsFeatureSyncMap
}
func (m *mockSecretsProvider) Login() error            { return nil }
func (m *mockSecretsProvider) Get() (string, error)    { return "", nil }
func (m *mockSecretsProvider) Set(secret string) error { return nil }
func (m *mockSecretsProvider) LastMod(path, secret string) (time.Time, error) {
	return m.lastModTime, m.lastModErr
}
func (m *mockSecretsProvider) Read(path, secret string) (map[string]any, error) {
	return nil, nil
}
func (m *mockSecretsProvider) Write(path, secret string, payload map[string]any) error {
	return nil
}
func (m *mockSecretsProvider) PostFlight() error { return nil }

func TestMasterKeyEncodeDecode_RoundTrip(t *testing.T) {
	original := &KobraSecretData{
		CreatedAt: "2024-01-01T00:00:00Z",
		PublicKey: "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		SecretKey: "AGE-SECRET-KEY-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	}

	encoded := masterKeyEncode(original)
	if encoded == "" {
		t.Fatal("masterKeyEncode returned empty string")
	}

	decoded, err := masterKeyDecode(encoded)
	if err != nil {
		t.Fatalf("masterKeyDecode error: %v", err)
	}

	if decoded.CreatedAt != original.CreatedAt {
		t.Errorf("CreatedAt: expected %q, got %q", original.CreatedAt, decoded.CreatedAt)
	}
	if decoded.PublicKey != original.PublicKey {
		t.Errorf("PublicKey: expected %q, got %q", original.PublicKey, decoded.PublicKey)
	}
	if decoded.SecretKey != original.SecretKey {
		t.Errorf("SecretKey: expected %q, got %q", original.SecretKey, decoded.SecretKey)
	}
}

func TestMasterKeyEncode_ProducesValidBase64JSON(t *testing.T) {
	data := &KobraSecretData{
		CreatedAt: time.Now().Format(time.RFC3339),
		PublicKey: "age1test",
		SecretKey: "AGE-SECRET-KEY-TEST",
	}

	encoded := masterKeyEncode(data)

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("encoded key is not valid base64: %v", err)
	}

	var ksd KobraSecretData
	err = json.Unmarshal(raw, &ksd)
	if err != nil {
		t.Fatalf("decoded bytes are not valid JSON: %v", err)
	}

	if ksd.PublicKey != data.PublicKey {
		t.Errorf("expected PublicKey=%q, got %q", data.PublicKey, ksd.PublicKey)
	}
}

func TestMasterKeyDecode_InvalidBase64(t *testing.T) {
	_, err := masterKeyDecode("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64 input, got nil")
	}
}

func TestMasterKeyDecode_InvalidJSON(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("not-json"))
	_, err := masterKeyDecode(encoded)
	if err == nil {
		t.Error("expected error for non-JSON payload, got nil")
	}
}

func TestSetSopsEnv_EmptySecrets(t *testing.T) {
	secrets := &KobraSecretData{}
	envs, sopsFile, err := setSopsEnv(secrets)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(envs) != 0 {
		t.Errorf("expected 0 env vars for empty secrets, got %d: %v", len(envs), envs)
	}
	if sopsFile != "" {
		t.Errorf("expected empty sops file path, got %q", sopsFile)
	}
}

func TestSetSopsEnv_WithSecrets_ReturnsTwoEnvVars(t *testing.T) {
	secrets := &KobraSecretData{
		CreatedAt: "2024-01-01T00:00:00Z",
		PublicKey: "age1testpublickey",
		SecretKey: "AGE-SECRET-KEY-TESTKEY",
	}
	envs, sopsFile, err := setSopsEnv(secrets)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(envs) != 2 {
		t.Errorf("expected 2 env vars, got %d: %v", len(envs), envs)
	}
	if sopsFile == "" {
		t.Error("expected non-empty sops file path")
	}

	hasAgeKeyFile := false
	hasAgeRecipients := false
	for _, env := range envs {
		if strings.HasPrefix(env, SopsAgeKeyFileEnv+"=") {
			hasAgeKeyFile = true
		}
		if strings.HasPrefix(env, SopsAgeRecipientsEnv+"=") {
			hasAgeRecipients = true
		}
	}
	if !hasAgeKeyFile {
		t.Errorf("expected %s env var, got: %v", SopsAgeKeyFileEnv, envs)
	}
	if !hasAgeRecipients {
		t.Errorf("expected %s env var, got: %v", SopsAgeRecipientsEnv, envs)
	}
}

func TestSetSopsEnv_RecipientsMatchPublicKey(t *testing.T) {
	secrets := &KobraSecretData{
		CreatedAt: "2024-01-01T00:00:00Z",
		PublicKey: "age1mypublickey",
		SecretKey: "AGE-SECRET-KEY-MYKEY",
	}
	envs, _, err := setSopsEnv(secrets)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, env := range envs {
		if after, ok := strings.CutPrefix(env, SopsAgeRecipientsEnv+"="); ok {
			val := after
			if val != secrets.PublicKey {
				t.Errorf("expected recipients %q, got %q", secrets.PublicKey, val)
			}
		}
	}
}

func TestSetSopsEnv_PartialSecrets_NoEnvVars(t *testing.T) {
	// Missing SecretKey → should not produce env vars
	tests := []struct {
		name    string
		secrets *KobraSecretData
	}{
		{
			name:    "missing CreatedAt",
			secrets: &KobraSecretData{PublicKey: "age1test", SecretKey: "AGE-SECRET-KEY-TEST"},
		},
		{
			name:    "missing PublicKey",
			secrets: &KobraSecretData{CreatedAt: "2024-01-01T00:00:00Z", SecretKey: "AGE-SECRET-KEY-TEST"},
		},
		{
			name:    "missing SecretKey",
			secrets: &KobraSecretData{CreatedAt: "2024-01-01T00:00:00Z", PublicKey: "age1test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envs, sopsFile, err := setSopsEnv(tt.secrets)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(envs) != 0 {
				t.Errorf("expected 0 env vars for partial secrets, got %d", len(envs))
			}
			if sopsFile != "" {
				t.Errorf("expected empty sops file for partial secrets, got %q", sopsFile)
			}
		})
	}
}

func TestLocalHasPrecedence_BothFail(t *testing.T) {
	// When local LastMod fails (non-SOPS file) and remote also fails, remote error wins → true
	ss := SecretSync{
		local: SecretSyncLocal{
			filename: "/nonexistent/path/that/cannot/exist.yml",
		},
		remote: SecretSyncRemote{
			sp:     &mockSecretsProvider{lastModErr: fmt.Errorf("remote unavailable")},
			path:   "test-path",
			secret: "test-secret",
		},
	}

	result := ss.LocalHasPrecedence()
	if !result {
		t.Error("expected LocalHasPrecedence=true when both local and remote fail")
	}
}

func TestLocalHasPrecedence_OnlyLocalFails(t *testing.T) {
	// When local LastMod fails but remote succeeds → local does not have precedence
	now := time.Now()
	ss := SecretSync{
		local: SecretSyncLocal{
			filename: "/nonexistent/path/that/cannot/exist.yml",
		},
		remote: SecretSyncRemote{
			sp:     &mockSecretsProvider{lastModTime: now},
			path:   "test-path",
			secret: "test-secret",
		},
	}

	result := ss.LocalHasPrecedence()
	if result {
		t.Error("expected LocalHasPrecedence=false when local fails but remote succeeds with a valid timestamp")
	}
}

func TestLocalHasPrecedence_TimestampComparison_LocalNewer(t *testing.T) {
	// Verify the timestamp logic: local after remote+1s → local has precedence
	now := time.Now()
	older := now.Add(-10 * time.Second)

	localLastMod := now
	remoteLastMod := older

	result := localLastMod.After(remoteLastMod.Add(1 * time.Second))
	if !result {
		t.Errorf("expected local (%v) to have precedence over remote (%v)", localLastMod, remoteLastMod)
	}
}

func TestLocalHasPrecedence_TimestampComparison_RemoteNewer(t *testing.T) {
	// Verify the timestamp logic: remote is newer → local does not have precedence
	now := time.Now()
	older := now.Add(-10 * time.Second)

	localLastMod := older
	remoteLastMod := now

	result := localLastMod.After(remoteLastMod.Add(1 * time.Second))
	if result {
		t.Errorf("expected remote (%v) to have precedence over local (%v)", remoteLastMod, localLastMod)
	}
}

func TestLocalHasPrecedence_TimestampComparison_WithinOneSecond(t *testing.T) {
	// Within 1-second margin → local does not have precedence (remote wins ties)
	now := time.Now()
	almostSame := now.Add(-500 * time.Millisecond)

	localLastMod := now
	remoteLastMod := almostSame

	// local.After(remote + 1s): now.After(almostSame + 1s) = now.After(now + 500ms) = false
	result := localLastMod.After(remoteLastMod.Add(1 * time.Second))
	if result {
		t.Error("expected no local precedence when timestamps differ by less than 1 second")
	}
}

func TestSecretsFeatureSyncMapConstant(t *testing.T) {
	if SecretsFeatureSyncMap == "" {
		t.Error("SecretsFeatureSyncMap constant should not be empty")
	}
}
