/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"

	"github.com/Cinemo-Product-Engineering/ipsctl/ipsctl"
	"github.com/kowabunga-cloud/common/klog"
)

const (
	IPSctlDebugEnv = "IPSCTL_DEBUG"
	IPSctlNoLog    = "IPSCTL_NOLOG"
)

func main() {
	// init our logger
	debug := os.Getenv(IPSctlDebugEnv)
	logLevel := "INFO"
	if debug == "1" {
		logLevel = "DEBUG"
	}

	enabled := true
	nolog := os.Getenv(IPSctlNoLog)
	if nolog == "1" {
		enabled = false
	}

	klog.Init("ipsctl", []klog.LoggerConfiguration{
		{
			Type:    "console",
			Enabled: enabled,
			Level:   logLevel,
		},
	})

	// parsing commands
	ipsctl.ParseCommands()
}
