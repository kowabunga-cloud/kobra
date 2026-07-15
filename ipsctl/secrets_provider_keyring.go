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
	"time"

	"github.com/99designs/keyring"
)

const (
	KeyringService = "ipsctl"
)

type SecretProviderKeyring struct {
	Keyring keyring.Keyring
	ID      string
}

func (s *SecretProviderKeyring) IsSupported(feature string) bool {
	return false
}

func (s *SecretProviderKeyring) Login() error {
	return nil
}

func (s *SecretProviderKeyring) PostFlight() error {
	return nil
}

func (s *SecretProviderKeyring) Get() (string, error) {
	data, err := s.Keyring.Get(s.ID)
	if err != nil {
		return "", nil
	}

	return string(data.Data), nil
}

func (s *SecretProviderKeyring) Set(secret string) error {
	return s.Keyring.Set(keyring.Item{
		Key:  s.ID,
		Data: []byte(secret),
	})
}

func (s *SecretProviderKeyring) LastMod(path, secret string) (time.Time, error) {
	return time.Time{}, nil
}

func (s *SecretProviderKeyring) Read(path, secret string) (map[string]any, error) {
	return map[string]any{}, nil
}

func (s *SecretProviderKeyring) Write(path, secret string, payload map[string]any) error {
	return nil
}

func NewSecretProviderKeyring(ptfCfg *PlatformConfig) (*SecretProviderKeyring, error) {
	cfg := keyring.Config{
		ServiceName: KeyringService,
	}

	ring, err := keyring.Open(cfg)
	if err != nil {
		return nil, err
	}

	return &SecretProviderKeyring{
		Keyring: ring,
		ID:      ptfCfg.Secrets.MasterKeyID,
	}, nil
}
