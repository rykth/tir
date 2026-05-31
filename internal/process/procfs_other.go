//go:build !linux

package process

import (
	"context"
	"errors"
)

// ProcfsResolver is the Linux-only resolver (on other platforms this stub
// exists so callers compile and NewProcfsResolver always returns an error)
type ProcfsResolver struct{}

// NewProcfsResolver returns an error on non-Linux platforms
func NewProcfsResolver() (*ProcfsResolver, error) {
	return nil, errors.New("procfs resolver: only supported on Linux")
}

// Method satisfies the Resolver interface
func (*ProcfsResolver) Method() string {
	return "unavailable"
}

// Run satisfies the Resolver interface
func (*ProcfsResolver) Run(ctx context.Context, out chan<- Update) error {
	_ = ctx
	close(out)
	return errors.New("procfs resolver: only supported on Linux")
}
