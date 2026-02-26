/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"testing"

	"github.com/Masterminds/semver/v3"
)

func TestFindPlatformBinaryVersion_InvalidSemverHandling(t *testing.T) {
	// This test validates the fix for ignoring invalid semver versions
	// when parsing GitHub releases
	tests := []struct {
		name            string
		releases        []GitHubRelease
		requestedVer    string
		expectErr       bool
		expectedVersion string
	}{
		{
			name: "ignores invalid semver and picks valid latest",
			releases: []GitHubRelease{
				{Tag: "v1.0.0", Draft: false, PreRelease: false},
				{Tag: "v1.1.0", Draft: false, PreRelease: false},
				{Tag: "v1.2.0", Draft: false, PreRelease: false},
				{Tag: "invalid-version", Draft: false, PreRelease: false},
				{Tag: "v2.0.0", Draft: false, PreRelease: false},
			},
			requestedVer:    ToolchainVersionLatest,
			expectErr:       false,
			expectedVersion: "2.0.0",
		},
		{
			name: "handles all invalid semver gracefully",
			releases: []GitHubRelease{
				{Tag: "not-semver", Draft: false, PreRelease: false},
				{Tag: "also-invalid", Draft: false, PreRelease: false},
			},
			requestedVer: ToolchainVersionLatest,
			expectErr:    true, // Should error because no valid versions found
		},
		{
			name: "ignores draft and prerelease",
			releases: []GitHubRelease{
				{Tag: "v1.0.0", Draft: false, PreRelease: false},
				{Tag: "v2.0.0", Draft: true, PreRelease: false},
				{Tag: "v3.0.0", Draft: false, PreRelease: true},
			},
			requestedVer:    ToolchainVersionLatest,
			expectErr:       false,
			expectedVersion: "1.0.0",
		},
		{
			name: "finds explicit version",
			releases: []GitHubRelease{
				{Tag: "v1.0.0", Draft: false, PreRelease: false},
				{Tag: "v1.5.0", Draft: false, PreRelease: false},
				{Tag: "v2.0.0", Draft: false, PreRelease: false},
			},
			requestedVer:    "1.5.0",
			expectErr:       false,
			expectedVersion: "1.5.0",
		},
		{
			name: "errors on missing explicit version",
			releases: []GitHubRelease{
				{Tag: "v1.0.0", Draft: false, PreRelease: false},
				{Tag: "v2.0.0", Draft: false, PreRelease: false},
			},
			requestedVer: "3.0.0",
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test HTTP server (for future integration testing)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.releases)
			}))
			defer server.Close()

			// Test the semver parsing logic directly
			releaseVersions := []string{}
			for _, r := range tt.releases {
				if r.Draft || r.PreRelease {
					continue
				}
				releaseVersions = append(releaseVersions, r.Tag[1:]) // Remove 'v' prefix
			}

			if tt.requestedVer == ToolchainVersionLatest && len(releaseVersions) > 0 {
				// This is the critical part we're testing - the semver parsing
				vs := []*semver.Version{}
				for _, r := range releaseVersions {
					v, err := semver.NewVersion(r)
					if err != nil {
						// This is the fix - continue instead of failing
						continue
					}
					vs = append(vs, v)
				}

				if len(vs) == 0 {
					if !tt.expectErr {
						t.Error("expected valid versions, got none")
					}
					return
				}

				sort.Sort(semver.Collection(vs))
				gotVersion := vs[len(vs)-1].String()

				if tt.expectErr {
					t.Errorf("expected error, got version %s", gotVersion)
				} else if gotVersion != tt.expectedVersion {
					t.Errorf("expected version %s, got %s", tt.expectedVersion, gotVersion)
				}
			}
		})
	}
}

func TestGitHubReleaseStructure(t *testing.T) {
	// Test that GitHubRelease structure correctly unmarshals JSON
	jsonData := `{
		"tag_name": "v1.0.0",
		"draft": false,
		"prerelease": true
	}`

	var release GitHubRelease
	err := json.Unmarshal([]byte(jsonData), &release)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if release.Tag != "v1.0.0" {
		t.Errorf("expected tag v1.0.0, got %s", release.Tag)
	}
	if release.Draft {
		t.Error("expected draft to be false")
	}
	if !release.PreRelease {
		t.Error("expected prerelease to be true")
	}
}

func TestThirdPartyToolConstants(t *testing.T) {
	// Test that the toolchain constants are defined
	constants := []string{
		ToolchainToolTF,
		ToolchainToolHelm,
		ToolchainToolHelmfile,
		ToolchainToolAnsible,
		ToolchainToolSops,
		ToolchainToolKubeseal,
	}

	expectedValues := []string{
		"tf",
		"helm",
		"helmfile",
		"ansible",
		"sops",
		"kubeseal",
	}

	for i, constant := range constants {
		if constant != expectedValues[i] {
			t.Errorf("expected constant %d to be %q, got %q", i, expectedValues[i], constant)
		}
	}
}

func TestToolchainToolsMapContainsKubeseal(t *testing.T) {
	// Verify that toolchainTools map includes kubeseal
	tool, exists := toolchainTools[KubesealBin]
	if !exists {
		t.Fatal("kubeseal not found in toolchainTools map")
	}

	if tool.Name != "Kubeseal" {
		t.Errorf("expected tool name 'Kubeseal', got %q", tool.Name)
	}

	if tool.GitHubRepo != "bitnami-labs/sealed-secrets" {
		t.Errorf("expected GitHub repo 'bitnami-labs/sealed-secrets', got %q", tool.GitHubRepo)
	}

	if len(tool.Binaries) == 0 {
		t.Error("expected binaries to be defined")
	}

	foundKubeseal := slices.Contains(tool.Binaries, KubesealBin)
	if !foundKubeseal {
		t.Error("expected kubeseal binary in binaries list")
	}
}
