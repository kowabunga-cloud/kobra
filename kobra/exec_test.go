/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBinExec(t *testing.T) {
	// Find a reliable binary for testing
	lsBin, err := LookupSystemBinary("echo")
	if err != nil {
		t.Skipf("echo binary not found: %v", err)
	}

	tests := []struct {
		name      string
		bin       string
		dir       string
		args      []string
		envs      []string
		expectErr bool
	}{
		{
			name:      "successful execution",
			bin:       lsBin,
			dir:       "",
			args:      []string{"test"},
			envs:      []string{},
			expectErr: false,
		},
		{
			name:      "execution with custom env",
			bin:       lsBin,
			dir:       "",
			args:      []string{"test"},
			envs:      []string{"TEST_VAR=test_value"},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := BinExec(tt.bin, tt.dir, tt.args, tt.envs)
			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestBinExecOut(t *testing.T) {
	echoBin, err := LookupSystemBinary("echo")
	if err != nil {
		t.Skipf("echo binary not found: %v", err)
	}

	tests := []struct {
		name           string
		bin            string
		dir            string
		args           []string
		envs           []string
		expectedOutput string
		expectErr      bool
	}{
		{
			name:           "capture output",
			bin:            echoBin,
			dir:            "",
			args:           []string{"hello world"},
			envs:           []string{},
			expectedOutput: "hello world",
			expectErr:      false,
		},
		{
			name:           "capture output with env",
			bin:            echoBin,
			dir:            "",
			args:           []string{"test"},
			envs:           []string{"TEST_VAR=value"},
			expectedOutput: "test",
			expectErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := BinExecOut(tt.bin, tt.dir, tt.args, tt.envs)
			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				output = strings.TrimSpace(output)
				if !strings.Contains(output, tt.expectedOutput) {
					t.Errorf("expected output to contain %q, got %q", tt.expectedOutput, output)
				}
			}
		})
	}
}

func TestBinExecOutNoErr(t *testing.T) {
	echoBin, err := LookupSystemBinary("echo")
	if err != nil {
		t.Skipf("echo binary not found: %v", err)
	}

	output, err := BinExecOutNoErr(echoBin, "", []string{"test output"}, []string{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	output = strings.TrimSpace(output)
	if !strings.Contains(output, "test output") {
		t.Errorf("expected output to contain 'test output', got %q", output)
	}
}

func TestBinExecWithDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file in the temp directory
	testFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	lsBin, err := LookupSystemBinary("ls")
	if err != nil {
		t.Skipf("ls binary not found: %v", err)
	}

	// Execute ls in the temp directory
	output, err := BinExecOut(lsBin, tmpDir, []string{}, []string{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "test.txt") {
		t.Errorf("expected output to contain 'test.txt', got %q", output)
	}
}

func TestBinExec_NonExistentBinary(t *testing.T) {
	err := BinExec("/nonexistent/binary", "", []string{}, []string{})
	if err == nil {
		t.Error("expected error for non-existent binary, got nil")
	}
}

func TestBinExec_InvalidDirectory(t *testing.T) {
	echoBin, err := LookupSystemBinary("echo")
	if err != nil {
		t.Skipf("echo binary not found: %v", err)
	}

	// Try to execute in a non-existent directory
	err = BinExec(echoBin, "/nonexistent/directory", []string{"test"}, []string{})
	if err == nil {
		t.Error("expected error for invalid directory, got nil")
	}
}
