/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"

	"github.com/kowabunga-cloud/kobra/kobra"
	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
)

const (
	KobraDebugEnv = "KOBRA_DEBUG"
)

func main() {
	// init our logger
	debug := os.Getenv(KobraDebugEnv)
	logLevel := "INFO"
	if debug == "1" {
		logLevel = "DEBUG"
	}
	klog.Init("kobra", []klog.LoggerConfiguration{
		{
			Type:    "console",
			Enabled: true,
			Level:   logLevel,
		},
	})

	// parsing commands
	kobra.ParseCommands()
}
