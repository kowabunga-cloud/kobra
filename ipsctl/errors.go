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
	"fmt"

	"github.com/kowabunga-cloud/common/klog"
)

func IPSctlError(format string, args ...any) error {
	err := fmt.Errorf(format, args...)
	klog.Errorf("%s", err)
	return err
}
