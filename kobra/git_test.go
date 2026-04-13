/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"testing"
)

func TestGitAuth_HTTP_BasicAuth(t *testing.T) {
	ptfCfg := &PlatformConfig{
		Git: PlatformConfigGit{
			Method: GitMethodHTTP,
			HTTP: PlatformConfigGitHTTP{
				Username: "user",
				Password: "pass",
			},
		},
	}

	auth, err := gitAuth(ptfCfg, "https://github.com/example/repo.git")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGitAuth_HTTP_TokenAuth(t *testing.T) {
	ptfCfg := &PlatformConfig{
		Git: PlatformConfigGit{
			Method: GitMethodHTTP,
			HTTP: PlatformConfigGitHTTP{
				Token: "ghp_myaccesstoken",
			},
		},
	}

	auth, err := gitAuth(ptfCfg, "https://github.com/example/repo.git")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth == nil {
		t.Fatal("expected non-nil auth method for token-based HTTP auth")
	}
}

func TestGitAuth_UnsupportedMethod(t *testing.T) {
	ptfCfg := &PlatformConfig{
		Git: PlatformConfigGit{
			Method: "ftp",
		},
	}

	// URL doesn't matter since method is overridden by ptfCfg.Git.Method
	_, err := gitAuth(ptfCfg, "https://example.com/repo.git")
	if err == nil {
		t.Error("expected error for unsupported git method, got nil")
	}
}

func TestGitAuth_HTTP_UsesConfigMethodOverURLScheme(t *testing.T) {
	// Even if URL is HTTPS, config method=http should be used
	ptfCfg := &PlatformConfig{
		Git: PlatformConfigGit{
			Method: GitMethodHTTP,
			HTTP: PlatformConfigGitHTTP{
				Username: "user",
				Password: "pass",
			},
		},
	}

	auth, err := gitAuth(ptfCfg, "https://github.com/example/repo.git")
	if err != nil {
		t.Fatalf("unexpected error with HTTPS URL and HTTP method override: %v", err)
	}
	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGitConstants(t *testing.T) {
	if GitOrigin != "origin" {
		t.Errorf("expected GitOrigin=%q, got %q", "origin", GitOrigin)
	}
	if GitDefaultUserSSH != "git" {
		t.Errorf("expected GitDefaultUserSSH=%q, got %q", "git", GitDefaultUserSSH)
	}
	if GitMethodSSH != "ssh" {
		t.Errorf("expected GitMethodSSH=%q, got %q", "ssh", GitMethodSSH)
	}
	if GitMethodHTTP != "http" {
		t.Errorf("expected GitMethodHTTP=%q, got %q", "http", GitMethodHTTP)
	}
}
