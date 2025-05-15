/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"github.com/99designs/keyring"
)

const (
	KeyringService = "kobra"
)

type SecretProviderKeyring struct {
	Keyring keyring.Keyring
	ID      string
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
