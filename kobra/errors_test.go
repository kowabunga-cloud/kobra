/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"testing"
)

func TestKobraError(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		args     []any
		expected string
	}{
		{
			name:     "simple error message",
			format:   "test error",
			args:     nil,
			expected: "test error",
		},
		{
			name:     "formatted error message",
			format:   "error: %s",
			args:     []any{"something failed"},
			expected: "error: something failed",
		},
		{
			name:     "multiple args",
			format:   "error %d: %s",
			args:     []any{42, "not found"},
			expected: "error 42: not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := KobraError(tt.format, tt.args...)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tt.expected {
				t.Errorf("expected error %q, got %q", tt.expected, err.Error())
			}
		})
	}
}
