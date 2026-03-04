/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"

	"github.com/kowabunga-cloud/common/klog"
	"github.com/kowabunga-cloud/kobra/kobra"
)

const (
	KobraDebugEnv = "KOBRA_DEBUG"
	KobraNoLog    = "KOBRA_NOLOG"
)

func main() {
	// init our logger
	debug := os.Getenv(KobraDebugEnv)
	logLevel := "INFO"
	if debug == "1" {
		logLevel = "DEBUG"
	}

	enabled := true
	nolog := os.Getenv(KobraNoLog)
	if nolog == "1" {
		enabled = false
	}

	klog.Init("kobra", []klog.LoggerConfiguration{
		{
			Type:    "console",
			Enabled: enabled,
			Level:   logLevel,
		},
	})

	// parsing commands
	kobra.ParseCommands()
}
