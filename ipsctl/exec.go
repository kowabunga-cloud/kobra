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

package ipsctl

import (
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/kowabunga-cloud/common/klog"
)

func binExec(bin, dir string, args, envs []string, stdout, stderr io.Writer) error {

	var cmd exec.Cmd

	binArgs := append([]string{bin}, args...)
	binEnvs := append(os.Environ(), envs...)

	cmd.Path = bin
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Args = binArgs
	cmd.Env = binEnvs
	cmd.Stdout = stdout
	cmd.Stdin = os.Stdin
	cmd.Stderr = stderr

	klog.Debugf("Running %s %s", strings.Join(envs[:], " "), strings.Join(cmd.Args[:], " "))
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func BinExec(bin, dir string, args, envs []string) error {
	return binExec(bin, dir, args, envs, os.Stdout, os.Stdout)
}

func BinExecOut(bin, dir string, args, envs []string) (string, error) {
	var outbuf strings.Builder
	err := binExec(bin, dir, args, envs, &outbuf, &outbuf)
	return outbuf.String(), err
}

func BinExecOutNoErr(bin, dir string, args, envs []string) (string, error) {
	var outbuf strings.Builder
	err := binExec(bin, dir, args, envs, &outbuf, nil)
	return outbuf.String(), err
}
