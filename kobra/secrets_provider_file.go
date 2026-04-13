/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type SecretProviderFile struct {
	Filename string
}

func (s *SecretProviderFile) IsSupported(feature string) bool {
	return false
}

func (s *SecretProviderFile) Login() error {
	return nil
}

func (s *SecretProviderFile) PostFlight() error {
	return nil
}

func (s *SecretProviderFile) Get() (string, error) {
	data, err := os.ReadFile(s.Filename)
	if err != nil {
		return "", nil
	}

	return string(data), nil
}

func (s *SecretProviderFile) Set(secret string) error {
	return os.WriteFile(s.Filename, []byte(secret), 0600)
}

func (s *SecretProviderFile) LastMod(path, secret string) (time.Time, error) {
	return time.Time{}, nil
}

func (s *SecretProviderFile) Read(path, secret string) (map[string]any, error) {
	return map[string]any{}, nil
}

func (s *SecretProviderFile) Write(path, secret string, payload map[string]any) error {
	return nil
}

func NewSecretProviderFile(ptfCfg *PlatformConfig) (*SecretProviderFile, error) {
	f := filepath.Clean(ptfCfg.Secrets.File.Path)
	if f == "" {
		return nil, fmt.Errorf("no file specified for secrets master key")
	}

	_, err := os.Stat(f)
	if errors.Is(err, os.ErrNotExist) {
		// create file if non-existent
		fd, err := os.Create(f)
		if err != nil {
			return nil, err
		}
		_ = fd.Close()

		err = os.Chmod(f, 0600)
		if err != nil {
			return nil, err
		}
	}

	return &SecretProviderFile{
		Filename: f,
	}, nil
}
