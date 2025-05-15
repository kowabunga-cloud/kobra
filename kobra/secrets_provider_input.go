/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"github.com/cqroot/prompt"
	"github.com/cqroot/prompt/input"

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
)

type SecretProviderInput struct{}

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

func NewSecretProviderInput(ptfCfg *PlatformConfig) (*SecretProviderInput, error) {
	return &SecretProviderInput{}, nil
}
