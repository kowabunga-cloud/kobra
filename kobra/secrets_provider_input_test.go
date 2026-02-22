/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"testing"
)

func TestSecretProviderInput_Login(t *testing.T) {
	provider := &SecretProviderInput{}
	err := provider.Login()
	if err != nil {
		t.Errorf("Login should not return error, got: %v", err)
	}
}

func TestSecretProviderInput_PostFlight(t *testing.T) {
	provider := &SecretProviderInput{}
	err := provider.PostFlight()
	if err != nil {
		t.Errorf("PostFlight should not return error, got: %v", err)
	}
}

func TestSecretProviderInput_Set(t *testing.T) {
	provider := &SecretProviderInput{}
	err := provider.Set("test_secret")
	if err != nil {
		t.Errorf("Set should not return error, got: %v", err)
	}
}

func TestNewSecretProviderInput(t *testing.T) {
	ptfCfg := &PlatformConfig{}
	provider, err := NewSecretProviderInput(ptfCfg)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if provider == nil {
		t.Error("expected provider, got nil")
	}
}
