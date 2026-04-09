/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cqroot/prompt"
	"github.com/cqroot/prompt/input"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"

	"github.com/kowabunga-cloud/common/klog"
)

const (
	VaultEndpointDefault  = "http://127.0.0.1:8200"
	VaultTokenEnvDefault  = "VAULT_TOKEN"
	VaultTokenFileDefault = ".vault-token"
	VaultMasterKeyID      = "kobra_master_key"
	VaultMountPathDefault = "secret"
	OneDaySeconds         = (60 * 60 * 24)
	OneMonthSeconds       = (OneDaySeconds * 30)
)

type SecretProviderHCP struct {
	ctx       context.Context
	Client    *vault.Client
	ID        string
	Mount     string
	Token     string
	TokenEnv  string
	TokenFile string
}

func (s *SecretProviderHCP) isTokenValid() error {
	resp, err := s.Client.Auth.TokenLookUpSelf(s.ctx)
	if err != nil {
		if vault.IsErrorStatus(err, http.StatusForbidden) {
			klog.Errorf("HCP Vault token is invalid, does not have permissions or is expired")
		}
		return err
	}

	klog.Debugf("Vault token is valid until %s", resp.Data["expire_time"])

	ttl, err := resp.Data["ttl"].(json.Number).Int64()
	if err != nil {
		return err
	}

	if ttl < OneMonthSeconds {
		klog.Warningf("Vault token is about to expire in less than a month, please renew it soon")
	}
	if ttl < OneDaySeconds {
		klog.Errorf("Vault token is about to expire in less than a day, please renew it soon")
	}

	return nil
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
		fileName = filepath.Clean(fileName)

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

	err := s.Client.SetToken(s.Token)
	if err != nil {
		return err
	}

	err = s.isTokenValid()
	if err != nil {
		return err
	}

	return nil
}

func (s *SecretProviderHCP) PostFlight() error {
	return nil
}

func (s *SecretProviderHCP) Get() (string, error) {
	r, err := s.Client.Secrets.KvV2Read(context.Background(), s.ID, vault.WithMountPath(s.Mount))
	if err != nil {
		klog.Errorf("Failed to read secret from Vault: %s", err)
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

	if err != nil {
		klog.Errorf("Failed to write secret to Vault: %s", err)
		return err
	}

	return nil
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
		ctx:       context.Background(),
		Client:    client,
		Mount:     mount,
		TokenEnv:  tokenEnv,
		TokenFile: tokenFile,
		ID:        ptfCfg.Secrets.MasterKeyID,
	}, nil
}
