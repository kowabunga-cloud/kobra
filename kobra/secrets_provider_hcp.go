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
	"strings"
	"time"

	"github.com/cqroot/prompt"
	"github.com/cqroot/prompt/input"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
)

const (
	VaultEndpointDefault  = "http://127.0.0.1:8200"
	VaultTokenEnvDefault  = "VAULT_TOKEN"
	VaultTokenFileDefault = ".vault-token"
	VaultMasterKeyID      = "kobra_master_key"
	VaultMountPathDefault = "secret"
)

type SecretProviderHCP struct {
	Client    *vault.Client
	ID        string
	Mount     string
	Token     string
	TokenEnv  string
	TokenFile string
}

func (s *SecretProviderHCP) Login() error {
	// try to find Vault's token from environment variable
	data, ok := os.LookupEnv(s.TokenEnv)
	if ok {
		s.Token = data
	}

	// not found, try to find Vault's token from file
	if s.Token == "" {
		fileName := s.TokenFile
		if fileName == VaultTokenFileDefault {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}

			fileName = fmt.Sprintf("%s/%s", home, VaultTokenFileDefault)
		}

		data, err := os.ReadFile(fileName)
		if err == nil {
			s.Token = string(data)
			s.Token = strings.ReplaceAll(s.Token, "\r\n", "")
			s.Token = strings.ReplaceAll(s.Token, "\r", "")
			s.Token = strings.ReplaceAll(s.Token, "\n", "")
		}
	}

	// still not found, ask for it
	if s.Token == "" {
		var err error
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
	return nil
}

func (s *SecretProviderHCP) Get() (string, error) {
	r, err := s.Client.Secrets.KvV2Read(context.Background(), s.ID, vault.WithMountPath(s.Mount))
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
		vault.WithMountPath(s.Mount),
	)

	return err
}

func NewSecretProviderHCP(ptfCfg *PlatformConfig) (*SecretProviderHCP, error) {
	endpoint := ptfCfg.Secrets.HCP.Endpoint
	if endpoint == "" {
		endpoint = VaultEndpointDefault
	}

	mount := ptfCfg.Secrets.HCP.Mount
	if mount == "" {
		mount = VaultMountPathDefault
	}

	tokenEnv := ptfCfg.Secrets.HCP.TokenEnv
	if tokenEnv == "" {
		tokenEnv = VaultTokenEnvDefault
	}

	tokenFile := ptfCfg.Secrets.HCP.TokenFile
	if tokenFile == "" {
		tokenFile = VaultTokenFileDefault
	}

	client, err := vault.New(
		vault.WithAddress(endpoint),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		return nil, err
	}

	return &SecretProviderHCP{
		Client:    client,
		Mount:     mount,
		TokenEnv:  tokenEnv,
		TokenFile: tokenFile,
		ID:        ptfCfg.Secrets.MasterKeyID,
	}, nil
}
