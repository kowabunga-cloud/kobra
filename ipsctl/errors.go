/*
 * Copyright (c) Cinemo GmbH. All rights reserved.
 *
 * This file is proprietary and confidential. Unauthorized copying,
 * distribution, or use, via any medium, is strictly prohibited without
 * prior written permission from Cinemo GmbH.
 */

package ipsctl

import (
	"fmt"

	"github.com/kowabunga-cloud/common/klog"
)

func IPSctlError(format string, args ...any) error {
	err := fmt.Errorf(format, args...)
	klog.Errorf("%s", err)
	return err
}
