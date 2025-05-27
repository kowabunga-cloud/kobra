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
	"os"
	"time"

	"filippo.io/age"

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
)

const (
	SopsCreateAtPrefix     = "# created: "
	SopsPublicKeyPrefix    = "# public key: "
	SopsAgeSecretKeyPrefix = "AGE-SECRET-KEY"

	SopsAgeKeyFileEnv    = "SOPS_AGE_KEY_FILE"
	SopsAgeRecipientsEnv = "SOPS_AGE_RECIPIENTS"
)

type KobraSecretData struct {
	CreatedAt string `json:"created_at"`
	PublicKey string `json:"public_key"`
	SecretKey string `json:"secret_key"`
}

type SecretsProvider interface {
	Login() error
	Get() (string, error)
	Set(secret string) error
	PostFlight() error
}

func GetSecretsProvider(ptfCfg *PlatformConfig) (SecretsProvider, error) {
	var spi SecretsProvider
	switch ptfCfg.Secrets.Provider {
	case SecretsProviderEnv:
		sp, err := NewSecretProviderEnv(ptfCfg)
		if err != nil {
			return nil, err
		}
		spi = sp
		return spi, nil
	case SecretsProviderFile:
		sp, err := NewSecretProviderFile(ptfCfg)
		if err != nil {
			return nil, err
		}
		spi = sp
		return spi, nil
	case SecretsProviderHCP:
		sp, err := NewSecretProviderHCP(ptfCfg)
		if err != nil {
			return nil, err
		}
		spi = sp
		return spi, nil
	case SecretsProviderInput:
		sp, err := NewSecretProviderInput(ptfCfg)
		if err != nil {
			return nil, err
		}
		spi = sp
		return spi, nil
	case SecretsProviderKeyring:
		sp, err := NewSecretProviderKeyring(ptfCfg)
		if err != nil {
			return nil, err
		}
		spi = sp
		return spi, nil
	}

	return nil, fmt.Errorf("unknown secret provider type")
}

func setSopsEnv(secrets *KobraSecretData) ([]string, string, error) {
	envs := []string{}

	// SOPS secret trick
	if secrets.CreatedAt == "" || secrets.PublicKey == "" || secrets.SecretKey == "" {
		return envs, "", nil
	}

	sopsFile, err := os.CreateTemp("", "sops_")
	if err != nil {
		return envs, "", KobraError("%s", err.Error())
	}

	sopsContent := fmt.Sprintf(`
%s%s
%s%s
%s`, SopsCreateAtPrefix, secrets.CreatedAt, SopsPublicKeyPrefix, secrets.PublicKey, secrets.SecretKey)
	_, err = sopsFile.WriteString(sopsContent)
	if err != nil {
		return envs, "", KobraError("%s", err.Error())
	}

	sopsName := sopsFile.Name()
	sops := fmt.Sprintf("%s=%s", SopsAgeKeyFileEnv, sopsName)
	envs = append(envs, sops)

	recipient := fmt.Sprintf("%s=%s", SopsAgeRecipientsEnv, secrets.PublicKey)
	envs = append(envs, recipient)

	return envs, sopsName, nil
}

func GetSecrets(ptfCfg *PlatformConfig) (*KobraSecretData, error) {
	// instantiate secrets provider
	sp, err := GetSecretsProvider(ptfCfg)
	if err != nil {
		return nil, KobraError("%s", err.Error())
	}

	// authenticate, when required
	err = sp.Login()
	if err != nil {
		return nil, KobraError("%s", err.Error())
	}

	// look for master key
	masterKey, err := sp.Get()
	if err != nil {
		return nil, KobraError("%s", err.Error())
	}

	// decode master key
	secrets, err := masterKeyDecode(masterKey)
	if err != nil {
		return nil, KobraError("%s", err.Error())
	}

	return secrets, nil
}

func secretsSopsCmd(cfg *KobraConfig, file string, params ...string) error {
	// read platform configuration
	ptfCfg, err := GetPlatformConfig()
	if err != nil {
		return KobraError("%s", err.Error())
	}

	secrets, err := GetSecrets(ptfCfg)
	if err != nil {
		return err
	}

	// set environment variables
	envs, sops, err := setSopsEnv(secrets)
	if err != nil {
		return err
	}
	if sops != "" {
		defer func() {
			_ = os.Remove(sops)
		}()
	}

	// set command-line arguments
	args := []string{}
	args = append(args, params...)
	args = append(args, file)

	sopsBin := LookupPluginBinary(SopsBin)
	return BinExec(sopsBin, "", args, envs)
}

func masterKeyEncode(data *KobraSecretData) string {
	secrets, err := json.Marshal(data)
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString([]byte(secrets))
}

func masterKeyDecode(key string) (*KobraSecretData, error) {
	sDec, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	var data KobraSecretData
	err = json.Unmarshal(sDec, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

func RunSecretsInit(cfg *KobraConfig) error {
	// read platform configuration
	ptfCfg, err := GetPlatformConfig()
	if err != nil {
		return KobraError("%s", err.Error())
	}

	// instantiate secrets provider
	sp, err := GetSecretsProvider(ptfCfg)
	if err != nil {
		return KobraError("%s", err.Error())
	}

	// look for existing master key, ignore non-existence
	err = sp.Login()
	if err != nil {
		return err
	}
	masterKey, err := sp.Get()

	if err == nil {
		// call provider post-actions, if any ...
		err = sp.PostFlight()
		if err != nil {
			return err
		}
	}

	if masterKey != "" {
		secrets, err := masterKeyDecode(masterKey)
		if err != nil {
			return KobraError("%s", err.Error())
		}

		if secrets.CreatedAt != "" || secrets.PublicKey != "" || secrets.SecretKey != "" {
			return KobraError("platform secrets have already been initialized. Won't be re-created")
		}
	}

	// no master key can be found, issue a new one
	klog.Info("Issuing new private/public master key ...")
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return KobraError("%s", err.Error())
	}

	data := KobraSecretData{
		CreatedAt: time.Now().Format(time.RFC3339),
		PublicKey: identity.Recipient().String(),
		SecretKey: identity.String(),
	}

	encKey := masterKeyEncode(&data)
	if encKey == "" {
		return KobraError("unable to convert and encode master key")
	}

	// push master key to secrets provider
	err = sp.Set(encKey)
	if err != nil {
		return KobraError("%s", err.Error())
	}

	klog.Infof("New SOPS private/public key pair has been successuflly generated and stored")

	return nil
}

func RunSecretsEncrypt(cfg *KobraConfig, file string) error {
	return secretsSopsCmd(cfg, file, "-e", "-i")
}

func RunSecretsEdit(cfg *KobraConfig, file string) error {
	return secretsSopsCmd(cfg, file)
}

func RunSecretsView(cfg *KobraConfig, file string) error {
	return secretsSopsCmd(cfg, file, "-d")
}

func RunSecretsGet(cfg *KobraConfig) error {
	// read platform configuration
	ptfCfg, err := GetPlatformConfig()
	if err != nil {
		return KobraError("%s", err.Error())
	}

	// instantiate secrets provider
	sp, err := GetSecretsProvider(ptfCfg)
	if err != nil {
		return KobraError("%s", err.Error())
	}

	// authenticate, when required
	err = sp.Login()
	if err != nil {
		return KobraError("%s", err.Error())
	}

	// look for master key
	masterKey, err := sp.Get()
	if err != nil {
		return KobraError("%s", err.Error())
	}

	fmt.Println(masterKey)

	return nil
}

func RunSecretsSet(cfg *KobraConfig, masterKey string) error {
	// read platform configuration
	ptfCfg, err := GetPlatformConfig()
	if err != nil {
		return KobraError("%s", err.Error())
	}

	// instantiate secrets provider
	sp, err := GetSecretsProvider(ptfCfg)
	if err != nil {
		return KobraError("%s", err.Error())
	}

	// look for existing master key, ignore non-existence
	err = sp.Login()
	if err != nil {
		return err
	}

	secrets, err := masterKeyDecode(masterKey)
	if err != nil {
		return KobraError("%s", err.Error())
	}

	if secrets.CreatedAt == "" || secrets.PublicKey == "" || secrets.SecretKey == "" {
		return KobraError("invalid master secret format")
	}

	// push master key to secrets provider
	err = sp.Set(masterKey)
	if err != nil {
		return KobraError("%s", err.Error())
	}

	klog.Infof("Manually provided SOPS private/public key pair has been successuflly stored")

	return nil

}
