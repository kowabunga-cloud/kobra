/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"slices"
	"testing"
)

func TestNewSealCommand(t *testing.T) {
	cmd := NewSealCommand()

	if cmd == nil {
		t.Fatal("expected command to be created, got nil")
		return
	}

	if cmd.Use != cmdSeal {
		t.Errorf("expected use %q, got %q", cmdSeal, cmd.Use)
	}

	if cmd.Short != cmdSealDesc {
		t.Errorf("expected short %q, got %q", cmdSealDesc, cmd.Short)
	}

	// Check aliases
	if len(cmd.Aliases) == 0 {
		t.Error("expected aliases to be set")
	} else {
		found := slices.Contains(cmd.Aliases, "seal")
		if !found {
			t.Error("expected 'seal' alias to be present")
		}
	}

	// Check that literal flag is required
	literalFlag := cmd.Flags().Lookup("literal")
	if literalFlag == nil {
		t.Error("expected literal flag to exist")
	}

	// Check other flags exist
	namespaceFlag := cmd.Flags().Lookup("namespace")
	if namespaceFlag == nil {
		t.Error("expected namespace flag to exist")
	}

	secretFlag := cmd.Flags().Lookup("secret")
	if secretFlag == nil {
		t.Error("expected secret flag to exist")
	}

	updateToolchainFlag := cmd.Flags().Lookup("update-toolchain")
	if updateToolchainFlag == nil {
		t.Error("expected update-toolchain flag to exist")
	}
}

func TestSealCommandFlags(t *testing.T) {
	cmd := NewSealCommand()

	tests := []struct {
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{"namespace", "n", ""},
		{"secret", "s", ""},
		{"literal", "l", ""},
		{"update-toolchain", "", "false"},
	}

	for _, tt := range tests {
		t.Run(tt.flagName, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.flagName)
			if flag == nil {
				t.Fatalf("flag %q not found", tt.flagName)
			}

			if tt.shorthand != "" && flag.Shorthand != tt.shorthand {
				t.Errorf("expected shorthand %q for flag %q, got %q",
					tt.shorthand, tt.flagName, flag.Shorthand)
			}

			if tt.defaultValue != "" && flag.DefValue != tt.defaultValue {
				t.Errorf("expected default value %q for flag %q, got %q",
					tt.defaultValue, tt.flagName, flag.DefValue)
			}
		})
	}
}
