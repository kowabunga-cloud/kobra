/*
 * Copyright (c) Cinemo GmbH. All rights reserved.
 *
 * This file is proprietary and confidential. Unauthorized copying,
 * distribution, or use, via any medium, is strictly prohibited without
 * prior written permission from Cinemo GmbH.
 */

package ipsctl

import (
	"testing"
)

func TestRootCmd(t *testing.T) {
	if RootCmd == nil {
		t.Error("expected RootCmd to be initialized, got nil")
	}

	if RootCmd.Use != "ipsctl" {
		t.Errorf("expected RootCmd.Use to be 'ipsctl', got %q", RootCmd.Use)
	}

	if RootCmd.Short == "" {
		t.Error("expected RootCmd.Short to be set")
	}
}

func TestConstants(t *testing.T) {
	if cmdToolchainUpdateDesc != "Check for toolchain update before run" {
		t.Errorf("unexpected cmdToolchainUpdateDesc value: %q", cmdToolchainUpdateDesc)
	}

	if cmdFailureStatus == "" {
		t.Error("expected cmdFailureStatus to be set")
	}
}
