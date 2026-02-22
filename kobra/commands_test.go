/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"testing"
)

func TestRootCmd(t *testing.T) {
	if RootCmd == nil {
		t.Error("expected RootCmd to be initialized, got nil")
	}

	if RootCmd.Use != "kobra" {
		t.Errorf("expected RootCmd.Use to be 'kobra', got %q", RootCmd.Use)
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
