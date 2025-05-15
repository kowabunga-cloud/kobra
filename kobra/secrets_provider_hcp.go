/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/99designs/keyring"
	"github.com/cqroot/prompt"
	"github.com/cqroot/prompt/input"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
)

const (
	VaultEndpointDefault      = "http://127.0.0.1:8200"
	VaultMasterKeyID          = "kobra_master_key"
	VaultMountPath            = "secret"
	VaultTokenKeyringGlobalID = "kobra-hcp-vault-token"
)

type SecretProviderHCP struct {
	Keyring keyring.Keyring
	Client  *vault.Client
	ID      string
	Token   string
}

func (s *SecretProviderHCP) Login() error {
	// try to find platform-specific Vault's token from local system keyring
	keyId := fmt.Sprintf("%s-%s", VaultTokenKeyringGlobalID, s.ID)
	data, err := s.Keyring.Get(keyId)
	if err == nil {
		s.Token = string(data.Data)
	}

	// not found, try to find global cross-platforms Vault's token from local system keyring
	if s.Token == "" {
		data, err := s.Keyring.Get(VaultTokenKeyringGlobalID)
		if err == nil {
			s.Token = string(data.Data)
		}
	}

	// still not found, ask for it
	if s.Token == "" {
		s.Token, err = prompt.New().Ask("Unlock Vault's token:").
			Input("", input.WithEchoMode(input.EchoPassword))
		if err != nil {
			if errors.Is(err, prompt.ErrUserQuit) {
				klog.Errorf("Error: %s", err)
				os.Exit(1)
			}
			return err
		}
	}

	return s.Client.SetToken(s.Token)
}

func (s *SecretProviderHCP) PostFlight() error {
	keyId := fmt.Sprintf("%s-%s", VaultTokenKeyringGlobalID, s.ID)
	_, err := s.Keyring.Get(keyId)
	if err != nil {
		val, err := prompt.New().Ask("Do you want to save token to local keyring ?").
			Choose([]string{"Yes", "No"})
		if err != nil {
			if errors.Is(err, prompt.ErrUserQuit) {
				klog.Errorf("Error: %s", err)
				os.Exit(1)
			}
			return err
		}

		if val == "Yes" {
			keyId := fmt.Sprintf("%s-%s", VaultTokenKeyringGlobalID, s.ID)
			return s.Keyring.Set(keyring.Item{
				Key:  keyId,
				Data: []byte(s.Token),
			})
		}
	}

	return nil
}

func (s *SecretProviderHCP) Get() (string, error) {
	r, err := s.Client.Secrets.KvV2Read(context.Background(), s.ID, vault.WithMountPath(VaultMountPath))
	if err != nil {
		return "", err
	}

	return r.Data.Data[VaultMasterKeyID].(string), nil
}

func (s *SecretProviderHCP) Set(secret string) error {
	_, err := s.Client.Secrets.KvV2Write(context.Background(), s.ID, schema.KvV2WriteRequest{
		Data: map[string]any{
			VaultMasterKeyID: secret,
		}},
		vault.WithMountPath(VaultMountPath),
	)

	return err
}

func NewSecretProviderHCP(ptfCfg *PlatformConfig) (*SecretProviderHCP, error) {
	endpoint := ptfCfg.Secrets.HCP.Endpoint
	if endpoint == "" {
		endpoint = VaultEndpointDefault
	}

	client, err := vault.New(
		vault.WithAddress(endpoint),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		return nil, err
	}

	cfg := keyring.Config{
		ServiceName: KeyringService,
	}

	ring, err := keyring.Open(cfg)
	if err != nil {
		return nil, err
	}

	return &SecretProviderHCP{
		Keyring: ring,
		Client:  client,
		ID:      ptfCfg.Secrets.MasterKeyID,
	}, nil
}
