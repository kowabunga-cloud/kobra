/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"net"
	"os"

	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh/agent"
)

const (
	SSHConfigUser     = "user"
	SSHConfigKey      = "IdentityFile"
	SSHAgentSocketEnv = "SSH_AUTH_SOCK"
)

func GetSSHCredentials(ptfCfg *PlatformConfig, bootstrap bool) (string, string, error) {
	var user, key string

	// if SSH credentials have been manually set in config file, we're good to go
	if bootstrap {
		if ptfCfg.SSH.Remote.User != "" && ptfCfg.SSH.Remote.KeyFile != "" {
			user = ptfCfg.SSH.Remote.User
			key = ptfCfg.SSH.Remote.KeyFile
		}
	} else {
		if ptfCfg.SSH.Bootstrap.User != "" && ptfCfg.SSH.Bootstrap.KeyFile != "" {
			user = ptfCfg.SSH.Bootstrap.User
			key = ptfCfg.SSH.Bootstrap.KeyFile
		}
	}

	if user == "" || key == "" {
		// alternatively, try to find info in SSH config files ($HOME/.ssh/config or /etc/ssh/ssh_config)
		hostCandidates := []string{
			"10.*",
			"192.168.*",
			"*",
		}
		for _, host := range hostCandidates {
			// check for a declared user
			user = ssh_config.Get(host, SSHConfigUser)

			// check for private key
			key = ssh_config.Get(host, SSHConfigKey)
			if key == "" {
				// if no key has been set, try to find one from ssh-agent
				authSock := os.Getenv(SSHAgentSocketEnv)
				if authSock == "" {
					continue
				}

				// connect to ssh-agent
				sshAgent, err := net.Dial("unix", authSock)
				if err != nil {
					continue
				}

				client := agent.NewClient(sshAgent)
				keys, _ := client.List()
				if len(keys) > 0 {
					// don't know which to use if multiple are found, so pick first one
					key = keys[0].Comment
				}
			}

			if user != "" && key != "" {
				break
			}
		}
	}

	if user != "" && key != "" {
		_, err := os.Stat(key)
		if err != nil {
			return user, key, KobraError("can't find SSH key file '%s'.", key)
		}

		// valid credentials have been found
		return user, key, nil
	}

	return "", "", KobraError("no private SSH user/key settings can be found or guessed. Please check your platform configuration file")
}
