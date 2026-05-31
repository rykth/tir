package process

import (
	"context"

	"github.com/rykth/tir/internal/conn"
)

// Update is one (connection-key, owning-process) attribution result
type Update struct {
	Key  conn.ConnKey
	PID  int32
	Name string
}

// Resolver streams Updates to the caller.
type Resolver interface {
	// Run drives the resolver until ctx is canceled
	Run(ctx context.Context, out chan<- Update) error
	// Method returns a short label ("procfs", "ebpf") for status display
	Method() string
}
