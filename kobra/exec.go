/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/kowabunga-cloud/kowabunga/kowabunga/common/klog"
)

func binExec(bin, dir string, args, envs []string, stdout io.Writer) error {

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
	cmd.Stderr = stdout

	klog.Debugf("Running %s %s", strings.Join(envs[:], " "), strings.Join(cmd.Args[:], " "))
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func BinExec(bin, dir string, args, envs []string) error {
	return binExec(bin, dir, args, envs, os.Stdout)
}

func BinExecOut(bin, dir string, args, envs []string) (string, error) {
	var outbuf strings.Builder
	err := binExec(bin, dir, args, envs, &outbuf)
	return outbuf.String(), err
}
