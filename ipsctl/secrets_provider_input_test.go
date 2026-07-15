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
