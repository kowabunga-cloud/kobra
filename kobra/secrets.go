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
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"filippo.io/age"
	"gopkg.in/yaml.v3"

	"github.com/kowabunga-cloud/common/klog"
)

const (
	SopsCreateAtPrefix     = "# created: "
	SopsPublicKeyPrefix    = "# public key: "
	SopsAgeSecretKeyPrefix = "AGE-SECRET-KEY"

	SopsAgeKeyFileEnv    = "SOPS_AGE_KEY_FILE"
	SopsAgeRecipientsEnv = "SOPS_AGE_RECIPIENTS"

	SecretsFeatureSyncMap = "SECRETS_FEATURE_SYNC_MAP"
)

type KobraSecretData struct {
	CreatedAt string `json:"created_at"`
	PublicKey string `json:"public_key"`
	SecretKey string `json:"secret_key"`
}

type SecretsProvider interface {
	IsSupported(feature string) bool
	Login() error
	Get() (string, error)
	Set(secret string) error
	LastMod(path, secret string) (time.Time, error)
	Read(path, secret string) (map[string]any, error)
	Write(path, secret string, payload map[string]any) error
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

func RunSecretsInit() error {
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

func secretsSopsSetEnv() (string, error) {
	// read platform configuration
	ptfCfg, err := GetPlatformConfig()
	if err != nil {
		return "", err
	}

	secrets, err := GetSecrets(ptfCfg)
	if err != nil {
		return "", err
	}

	// set environment variables
	envs, sops, err := setSopsEnv(secrets)
	if err != nil {
		return "", err
	}

	for _, e := range envs {
		s := strings.Split(e, "=")
		err := os.Setenv(s[0], s[1])
		if err != nil {
			return "", err
		}
	}

	return sops, nil
}

func RunSecretsEncrypt(file string) error {
	return SopsEncryptFile(file)
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src) // #nosec G304
	if err != nil {
		return err
	}
	defer func() {
		_ = sourceFile.Close()
	}()

	destFile, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644) // #nosec G302,G304
	if err != nil {
		return err
	}
	defer func() {
		_ = destFile.Close()
	}()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	return destFile.Sync()
}

type SecretSync struct {
	local  SecretSyncLocal
	remote SecretSyncRemote
}

func (s *SecretSync) LocalHasPrecedence() bool {
	// secret file synchronisation with remote secrets provider is expected
	localHasPrecedence := true

	// check which end is the most up-to-date (source of truth)
	err := s.local.LastMod()
	if err != nil {
		// Local file either do not yet exist or is pure garbage (non SOPS file).
		// Priority goes to remote secret, overwrite local file with it
		localHasPrecedence = false
	}

	err = s.remote.LastMod()
	if err != nil {
		// remote secret either do not yet exist or is inaccessible (ACL issue)
		localHasPrecedence = true
	}

	// if both timestamps and valid (local and remote secrets exist), compare them and decide which one has precedence
	if !s.local.lastMod.IsZero() && !s.remote.lastMod.IsZero() {
		localHasPrecedence = s.local.lastMod.After(s.remote.lastMod.Add(1 * time.Second))
	}

	klog.Debugf("Local file has precedence: %t", localHasPrecedence)
	return localHasPrecedence
}

func (s *SecretSync) EditAndSync() error {
	var err error

	if s.remote.sp.IsSupported(SecretsFeatureSyncMap) {
		// if remote secret is more recent than local file, or local file is not a valid SOPS file,
		// start by overwriting local file with remote secret's content
		if !s.LocalHasPrecedence() {
			_ = s.local.Decrypt()
			// no error check: file may simply not exist yet

			err = s.remote.Decrypt()
			if err != nil {
				return err
			}

			// check for any changes and update local secret if needed
			if !reflect.DeepEqual(s.local.data, s.remote.data) {
				klog.Infof("Content diverge, syncing remote secret %s/%s to local secrets file %s", s.remote.path, s.remote.secret, s.local.filename)
				s.local.data = s.remote.data
				err = s.local.Encrypt()
				if err != nil {
					return err
				}
			}
		}
	}

	// edit and encrypt local file
	err = SopsEditFile(s.local.filename)
	if err != nil {
		klog.Infof("Error editing local file, aborting sync: %s", err)
		return err
	}

	if s.remote.sp.IsSupported(SecretsFeatureSyncMap) {
		// unconditionnally, read and decode it back
		err = s.local.Decrypt()
		if err != nil {
			return err
		}

		// check for any changes and update remote secret if needed
		if !reflect.DeepEqual(s.local.data, s.remote.data) {
			// write local secrets back to remote secrets provider
			klog.Infof("Content diverge, syncing secrets file %s to remote secret %s/%s", s.local.filename, s.remote.path, s.remote.secret)
			s.remote.data = s.local.data
			err = s.remote.Encrypt()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func NewSecretSync(ptfCfg *PlatformConfig, file, path, secret string) (SecretSync, error) {
	// instantiate secrets provider
	sp, err := GetSecretsProvider(ptfCfg)
	if err != nil {
		return SecretSync{}, err
	}

	// authenticate, when required
	err = sp.Login()
	if err != nil {
		return SecretSync{}, err
	}

	return SecretSync{
		local: SecretSyncLocal{
			filename: file,
		},
		remote: SecretSyncRemote{
			sp:     sp,
			path:   path,
			secret: secret,
		},
	}, nil
}

type SecretSyncLocal struct {
	filename string
	lastMod  time.Time
	data     map[string]any
}

func (s *SecretSyncLocal) LastMod() error {
	lastMod, isSops, _ := getSopsLastModified(s.filename)
	if !isSops {
		return fmt.Errorf("not a SOPS file")
	}
	klog.Debugf("Local SOPS file last modified at: %s", lastMod)
	s.lastMod = lastMod
	return nil
}

func (s *SecretSyncLocal) Encrypt() error {
	// write data to temporary file
	payload, err := yaml.Marshal(s.data)
	if err != nil {
		return err
	}

	tmpDst, err := os.CreateTemp("", "*.yaml")
	if err != nil {
		return err
	}
	defer func() {
		_ = tmpDst.Close()
	}()
	defer func() {
		_ = os.Remove(tmpDst.Name())
	}()

	_, err = tmpDst.Write(payload)
	if err != nil {
		return err
	}

	_ = tmpDst.Close()

	// encrypt temporary file with sops
	err = SopsEncryptFile(tmpDst.Name())
	if err != nil {
		return err
	}

	// replace target file with temporary file
	err = copyFile(tmpDst.Name(), s.filename)
	if err != nil {
		return err
	}

	klog.Debugf("Data written to local SOPS file: %s", s.filename)
	return nil
}

func (s *SecretSyncLocal) Decrypt() error {
	tmpDst, err := os.CreateTemp("", "")
	if err != nil {
		return err
	}
	defer func() {
		_ = tmpDst.Close()
	}()
	defer func() {
		_ = os.Remove(tmpDst.Name())
	}()

	klog.Debugf("Reading from local SOPS file %s", s.filename)
	err = sopsDecodefile(s.filename, tmpDst)
	if err != nil {
		return err
	}

	err = tmpDst.Sync()
	if err != nil {
		return err
	}

	_, err = tmpDst.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	contents, err := io.ReadAll(tmpDst)
	if err != nil {
		return err
	}

	var data map[string]any
	err = yaml.Unmarshal(contents, &data)
	if err != nil {
		return err
	}

	s.data = data
	//klog.Debugf("Data read from local SOPS file: %v", s.data)

	return nil
}

type SecretSyncRemote struct {
	sp      SecretsProvider
	path    string
	secret  string
	lastMod time.Time
	data    map[string]any
}

func (s *SecretSyncRemote) LastMod() error {
	lastMod, err := s.sp.LastMod(s.path, s.secret)
	if err != nil {
		return err
	}
	s.lastMod = lastMod
	klog.Debugf("Remote SP secret last modified at: %s", lastMod)
	return nil
}

func (s *SecretSyncRemote) Encrypt() error {
	klog.Debugf("Writing to remote %s/%s", s.path, s.secret)
	return s.sp.Write(s.path, s.secret, s.data)
}

func (s *SecretSyncRemote) Decrypt() error {
	// read and decode remote secret
	klog.Debugf("Reading from remote %s/%s", s.path, s.secret)
	payload, err := s.sp.Read(s.path, s.secret)
	if err != nil {
		return err
	}

	s.data = payload
	//klog.Debugf("Data read from remote secret: %v", payload)
	return nil
}

func RunSecretsEdit(file string) error {
	ptfDir, err := LookupPlatformDir()
	if err != nil {
		return KobraError("%s", err.Error())
	}

	// read platform configuration
	ptfCfg, err := GetPlatformConfig()
	if err != nil {
		return KobraError("%s", err.Error())
	}

	// look for file absolute path
	abs, err := filepath.Abs(file)
	if err != nil {
		return err
	}

	// look if target file is part of secrets sync maps, if any
	for _, m := range ptfCfg.Secrets.SyncMaps {
		sf := fmt.Sprintf("%s/%s", ptfDir, m.SopsFile)
		asf, err := filepath.Abs(sf)
		if err != nil {
			return err
		}

		if asf == abs {
			// secret file synchronisation with remote secrets provider is expected
			ss, err := NewSecretSync(ptfCfg, abs, m.Path, m.Secret)
			if err != nil {
				return err
			}

			return ss.EditAndSync()
		}
	}

	// fallback: no secrets sync map found for the target file, proceed with local edit only
	return SopsEditFile(file)
}

func RunSecretsView(file string) error {
	return SopsViewFile(file)
}

func RunSecretsGet() error {
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

func RunSecretsSet(masterKey string) error {
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
