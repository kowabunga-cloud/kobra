/*
 * Copyright (c) Cinemo GmbH. All rights reserved.
 *
 * Originally licensed under the Apache License, Version 2.0
 * (see https://www.apache.org/licenses/LICENSE-2.0.txt).
 * Benjamin Zores, original author, granted Cinemo GmbH explicit rights
 * to relicense and use this work under proprietary terms.
 *
 * This file is proprietary and confidential. Unauthorized copying,
 * distribution, or use, via any medium, is strictly prohibited without
 * prior written permission from Cinemo GmbH.
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
