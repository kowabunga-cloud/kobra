/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"time"

	"github.com/cqroot/prompt"
	"github.com/cqroot/prompt/input"

	"github.com/kowabunga-cloud/common/klog"
)

type SecretProviderInput struct{}

func (s *SecretProviderInput) IsSupported(feature string) bool {
	return false
}

func (s *SecretProviderInput) Login() error {
	return nil
}

func (s *SecretProviderInput) PostFlight() error {
	return nil
}

func (s *SecretProviderInput) Get() (string, error) {
	return prompt.New().Ask("Platform's master key:").
		Input("", input.WithEchoMode(input.EchoPassword))
}

func (s *SecretProviderInput) Set(secret string) error {
	klog.Infof("Please keep the following plaform master key safe:")
	klog.Infof("  %s", secret)
	return nil
}

func (s *SecretProviderInput) LastMod(path, secret string) (time.Time, error) {
	return time.Time{}, nil
}

func (s *SecretProviderInput) Read(path, secret string) (map[string]any, error) {
	return map[string]any{}, nil
}

func (s *SecretProviderInput) Write(path, secret string, payload map[string]any) error {
	return nil
}

func NewSecretProviderInput(ptfCfg *PlatformConfig) (*SecretProviderInput, error) {
	return &SecretProviderInput{}, nil
}
