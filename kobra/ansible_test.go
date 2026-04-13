/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"regexp"
	"testing"
)

func TestCompilePatterns_SinglePattern(t *testing.T) {
	re, err := compilePatterns([]string{"password"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if re == nil {
		t.Fatal("expected non-nil regexp")
	}

	shouldMatch := []string{"password", "my_password", "password_hash"}
	for _, s := range shouldMatch {
		if !re.MatchString(s) {
			t.Errorf("expected pattern to match %q", s)
		}
	}

	shouldNot := []string{"username", "host", "port"}
	for _, s := range shouldNot {
		if re.MatchString(s) {
			t.Errorf("expected pattern not to match %q", s)
		}
	}
}

func TestCompilePatterns_MultiplePatterns(t *testing.T) {
	re, err := compilePatterns([]string{"password", "secret", "token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	shouldMatch := []string{"password", "api_secret", "auth_token"}
	for _, s := range shouldMatch {
		if !re.MatchString(s) {
			t.Errorf("expected pattern to match %q", s)
		}
	}

	shouldNot := []string{"username", "host"}
	for _, s := range shouldNot {
		if re.MatchString(s) {
			t.Errorf("expected pattern not to match %q", s)
		}
	}
}

func TestCompilePatterns_AnchoredPattern(t *testing.T) {
	re, err := compilePatterns([]string{"^private_key$"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !re.MatchString("private_key") {
		t.Error("expected pattern to match exact string 'private_key'")
	}
	if re.MatchString("my_private_key") {
		t.Error("expected anchored pattern not to match 'my_private_key'")
	}
}

func TestCompilePatterns_InvalidRegex(t *testing.T) {
	_, err := compilePatterns([]string{"[invalid"})
	if err == nil {
		t.Error("expected error for invalid regex, got nil")
	}
}

func TestWalkAndReplace_FlatMap(t *testing.T) {
	re := regexp.MustCompile("(password)|(secret)")
	data := map[string]any{
		"username": "admin",
		"password": "s3cr3t",
		"host":     "localhost",
	}

	result := walkAndReplace(data, re, "REDACTED")
	m := result.(map[string]any)

	if m["password"] != "REDACTED" {
		t.Errorf("expected REDACTED for password, got %v", m["password"])
	}
	if m["username"] != "admin" {
		t.Errorf("expected admin for username, got %v", m["username"])
	}
	if m["host"] != "localhost" {
		t.Errorf("expected localhost for host, got %v", m["host"])
	}
}

func TestWalkAndReplace_NestedMap(t *testing.T) {
	re := regexp.MustCompile("password")
	data := map[string]any{
		"database": map[string]any{
			"host":     "db.example.com",
			"password": "dbpass",
		},
		"name": "myapp",
	}

	result := walkAndReplace(data, re, "REDACTED")
	m := result.(map[string]any)

	db := m["database"].(map[string]any)
	if db["password"] != "REDACTED" {
		t.Errorf("expected REDACTED for nested password, got %v", db["password"])
	}
	if db["host"] != "db.example.com" {
		t.Errorf("expected db.example.com for host, got %v", db["host"])
	}
	if m["name"] != "myapp" {
		t.Errorf("expected myapp for name, got %v", m["name"])
	}
}

func TestWalkAndReplace_Slice(t *testing.T) {
	re := regexp.MustCompile("token")
	data := []any{
		map[string]any{"token": "abc123", "name": "app1"},
		map[string]any{"token": "def456", "name": "app2"},
	}

	result := walkAndReplace(data, re, "REDACTED")
	s := result.([]any)

	for i, item := range s {
		m := item.(map[string]any)
		if m["token"] != "REDACTED" {
			t.Errorf("index %d: expected REDACTED for token, got %v", i, m["token"])
		}
	}
	if s[0].(map[string]any)["name"] != "app1" {
		t.Errorf("expected app1 for name, got %v", s[0].(map[string]any)["name"])
	}
}

func TestWalkAndReplace_NoMatch(t *testing.T) {
	re := regexp.MustCompile("password")
	data := map[string]any{
		"username": "admin",
		"host":     "localhost",
		"port":     8080,
	}

	result := walkAndReplace(data, re, "REDACTED")
	m := result.(map[string]any)

	if m["username"] != "admin" {
		t.Errorf("expected admin, got %v", m["username"])
	}
	if m["host"] != "localhost" {
		t.Errorf("expected localhost, got %v", m["host"])
	}
	if m["port"] != 8080 {
		t.Errorf("expected 8080, got %v", m["port"])
	}
}

func TestWalkAndReplace_DeepNesting(t *testing.T) {
	re := regexp.MustCompile("secret")
	data := map[string]any{
		"level1": map[string]any{
			"level2": map[string]any{
				"secret": "hidden",
				"public": "visible",
			},
		},
	}

	result := walkAndReplace(data, re, "REDACTED")
	m := result.(map[string]any)
	l1 := m["level1"].(map[string]any)
	l2 := l1["level2"].(map[string]any)

	if l2["secret"] != "REDACTED" {
		t.Errorf("expected REDACTED for deeply nested secret, got %v", l2["secret"])
	}
	if l2["public"] != "visible" {
		t.Errorf("expected visible for public, got %v", l2["public"])
	}
}

func TestWalkAndReplace_MatchingKeyReplacedRegardlessOfValue(t *testing.T) {
	re := regexp.MustCompile("password")
	data := map[string]any{
		"password": nil,
	}

	result := walkAndReplace(data, re, "REDACTED")
	m := result.(map[string]any)

	if m["password"] != "REDACTED" {
		t.Errorf("expected REDACTED even for nil value, got %v", m["password"])
	}
}

func TestAnsibleInventoryActionConstants(t *testing.T) {
	if cmdAnsibleInventoryActionExport != "export" {
		t.Errorf("expected export, got %q", cmdAnsibleInventoryActionExport)
	}
	if cmdAnsibleInventoryActionGraph != "graph" {
		t.Errorf("expected graph, got %q", cmdAnsibleInventoryActionGraph)
	}
	if cmdAnsibleInventoryActionHost != "host" {
		t.Errorf("expected host, got %q", cmdAnsibleInventoryActionHost)
	}
	if cmdAnsibleInventoryActionList != "list" {
		t.Errorf("expected list, got %q", cmdAnsibleInventoryActionList)
	}
}

func TestAnsibleInventorySubCommandsMap(t *testing.T) {
	expectedActions := []string{
		cmdAnsibleInventoryActionExport,
		cmdAnsibleInventoryActionGraph,
		cmdAnsibleInventoryActionHost,
		cmdAnsibleInventoryActionList,
	}
	for _, action := range expectedActions {
		if _, ok := ansibleInventorySubCommands[action]; !ok {
			t.Errorf("expected action %q to be registered in ansibleInventorySubCommands", action)
		}
	}
}
