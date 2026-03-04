/*
 * Copyright (c) The Kowabunga Project
 * Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
 * SPDX-License-Identifier: Apache-2.0
 */

package kobra

import (
	"fmt"

	"github.com/kowabunga-cloud/common/klog"
)

func KobraError(format string, args ...any) error {
	err := fmt.Errorf(format, args...)
	klog.Errorf("%s", err)
	return err
}
