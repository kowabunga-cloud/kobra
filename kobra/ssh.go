/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

const (
	SSHConfigUser     = "user"
	SSHConfigKey      = "IdentityFile"
	SSHAgentSocketEnv = "SSH_AUTH_SOCK"
)

func expandTilde(p string) (string, error) {
	if !strings.HasPrefix(p, "~") {
		return p, nil // nothing to do
	}

	// Fast path for the current user: "~" or "~/..."
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, p[2:]), nil // strip "~/" and join
	}

	// If the tilde is followed by a username (e.g. "~bob/foo"), we need to look up that user explicitly.
	sepIdx := strings.IndexAny(p, `/\`) // first slash/backslash after "~bob"
	if sepIdx == -1 {
		sepIdx = len(p)
	}
	username := p[1:sepIdx] // everything between "~" and the separator
	usr, err := user.Lookup(username)
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, p[sepIdx+1:]), nil
}

func GetSSHCredentials(ptfCfg *PlatformConfig, bootstrap bool) (string, string, error) {
	var user, key string

	// if SSH credentials have been manually set in config file, we're good to go
	if bootstrap {
		if ptfCfg.SSH.Bootstrap.User != "" && ptfCfg.SSH.Bootstrap.KeyFile != "" {
			user = ptfCfg.SSH.Bootstrap.User
			key = ptfCfg.SSH.Bootstrap.KeyFile
		}
	} else {
		if ptfCfg.SSH.Remote.User != "" && ptfCfg.SSH.Remote.KeyFile != "" {
			user = ptfCfg.SSH.Remote.User
			key = ptfCfg.SSH.Remote.KeyFile
		}
	}

	if key != "" && strings.HasPrefix(key, "~/") {
		expanded, err := expandTilde(key)
		if err != nil {
			return "", "", err
		}
		key = expanded
	}

	if key != "" {
		_, err := os.Stat(key)
		if err != nil {
			return user, key, KobraError("can't find SSH key file '%s'.", key)
		}
	}

	// credentials have been found
	return user, key, nil
}
