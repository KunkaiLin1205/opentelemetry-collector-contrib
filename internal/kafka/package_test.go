// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// Ignore goroutines created by google.DefaultTokenSource for OAuth token refresh
	// These are expected background goroutines that manage token lifecycle
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
		goleak.IgnoreTopFunction("net.(*netFD).connect"),
		goleak.IgnoreTopFunction("net.(*netFD).connect.func2"),
	)
}
