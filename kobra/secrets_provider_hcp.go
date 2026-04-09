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
	VaultEndpointDefault     = "http://127.0.0.1:8200"
	VaultTokenEnvDefault     = "VAULT_TOKEN"
	VaultTokenFileDefault    = ".vault-token"
	VaultUsernameEnvDefault  = "VAULT_USERNAME"
	VaultUsernameFileDefault = ".vault-username"
	VaultPasswordEnvDefault  = "VAULT_PASSWORD"
	VaultPasswordFileDefault = ".vault-password"
	VaultMasterKeyID         = "kobra_master_key"
	VaultMountPathDefault    = "secret"
	OneDaySeconds            = (60 * 60 * 24)
	OneMonthSeconds          = (OneDaySeconds * 30)
)

type SecretProviderHCP struct {
	ctx          context.Context
	Client       *vault.Client
	ID           string
	Mount        string
	AuthMethod   string
	Token        string
	TokenEnv     string
	TokenFile    string
	UsernameEnv  string
	UsernameFile string
	PasswordEnv  string
	PasswordFile string
}

func (s *SecretProviderHCP) readFromFile(src, dflt string) (string, error) {
	fileName := src
	if fileName == dflt {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		fileName = fmt.Sprintf("%s/%s", home, dflt)
	}
	fileName = filepath.Clean(fileName)

	data, err := os.ReadFile(fileName)
	if err != nil {
		return "", err
	}

	res := string(data)
	res = strings.ReplaceAll(res, "\r\n", "")
	res = strings.ReplaceAll(res, "\r", "")
	res = strings.ReplaceAll(res, "\n", "")

	return res, nil
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

func (s *SecretProviderHCP) UserpassLogin(username, password string) error {
	var resp *vault.Response[map[string]any]
	var err error

	switch s.AuthMethod {
	case SecretsHCPAuthMethodLdap:
		resp, err = s.Client.Auth.LdapLogin(s.ctx, username, schema.LdapLoginRequest{
			Password: password,
		})
	default:
		resp, err = s.Client.Auth.UserpassLogin(s.ctx, username, schema.UserpassLoginRequest{
			Password: password,
		})
	}

	if err != nil {
		return err
	}

	s.Token = resp.Auth.ClientToken

	return nil
}

func (s *SecretProviderHCP) Login() error {
	var err error

	// Try #1: Environment variable for token
	klog.Debugf("Trying Vault token-authentication from environment variable")
	data, ok := os.LookupEnv(s.TokenEnv)
	if ok {
		s.Token = data
	}

	// Try #2: File for token
	if s.Token == "" {
		klog.Debugf("Trying Vault token-authentication from file")
		s.Token, err = s.readFromFile(s.TokenFile, VaultTokenFileDefault)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	// Try #3: Environment variables for username and password
	if s.Token == "" {
		klog.Debugf("Trying Vault user/pass-authentication from environment variable")
		username, usernameOk := os.LookupEnv(s.UsernameEnv)
		password, passwordOk := os.LookupEnv(s.PasswordEnv)
		if usernameOk && passwordOk {
			err = s.UserpassLogin(username, password)
			if err != nil {
				return err
			}
		}
	}

	// Try #4: username and password from files
	if s.Token == "" {
		klog.Debugf("Trying Vault user/pass-authentication from files")
		username, err := s.readFromFile(s.UsernameFile, VaultUsernameFileDefault)
		if err != nil && !os.IsNotExist(err) {
			return err
		}

		password, err := s.readFromFile(s.PasswordFile, VaultPasswordFileDefault)
		if err != nil && !os.IsNotExist(err) {
			return err
		}

		err = s.UserpassLogin(username, password)
		if err != nil {
			return err
		}
	}

	// Try #5: still not found, ask for it
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

	err = s.Client.SetToken(s.Token)
	if err != nil {
		return err
	}

	err = s.isTokenValid()
	if err != nil {
		return err
	}

	// cascade the environment variable to children processes
	return os.Setenv("VAULT_TOKEN", s.Token)
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

	authMethod := ptfCfg.Secrets.HCP.AuthMethod
	if authMethod == "" {
		authMethod = SecretsHCPAuthMethodCredentials
	}

	tokenEnv := ptfCfg.Secrets.HCP.TokenEnv
	if tokenEnv == "" {
		tokenEnv = VaultTokenEnvDefault
	}

	tokenFile := ptfCfg.Secrets.HCP.TokenFile
	if tokenFile == "" {
		tokenFile = VaultTokenFileDefault
	}

	usernameEnv := ptfCfg.Secrets.HCP.UsernameEnv
	if usernameEnv == "" {
		usernameEnv = VaultUsernameEnvDefault
	}

	usernameFile := ptfCfg.Secrets.HCP.UsernameFile
	if usernameFile == "" {
		usernameFile = VaultUsernameFileDefault
	}

	passwordEnv := ptfCfg.Secrets.HCP.PasswordEnv
	if passwordEnv == "" {
		passwordEnv = VaultPasswordEnvDefault
	}

	passwordFile := ptfCfg.Secrets.HCP.PasswordFile
	if passwordFile == "" {
		passwordFile = VaultPasswordFileDefault
	}

	client, err := vault.New(
		vault.WithAddress(endpoint),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		return nil, err
	}

	return &SecretProviderHCP{
		ctx:          context.Background(),
		Client:       client,
		Mount:        mount,
		AuthMethod:   authMethod,
		TokenEnv:     tokenEnv,
		TokenFile:    tokenFile,
		UsernameEnv:  usernameEnv,
		UsernameFile: usernameFile,
		PasswordEnv:  passwordEnv,
		PasswordFile: passwordFile,
		ID:           ptfCfg.Secrets.MasterKeyID,
	}, nil
}
