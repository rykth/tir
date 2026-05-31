//go:build !linux

package process

import (
	"context"
	"errors"
)

// EBPFResolver is the Linux-only resolver; on other platforms this stub
// exists so callers compile. NewEBPFResolver always returns an error.
type EBPFResolver struct{}

// NewEBPFResolver returns an error on non-Linux platforms
func NewEBPFResolver() (*EBPFResolver, error) {
	return nil, errors.New("ebpf resolver: only supported on Linux")
}

// Method satisfies the Resolver interface
func (*EBPFResolver) Method() string {
	return "unavailable"
}

// Run satisfies the Resolver interface
func (*EBPFResolver) Run(ctx context.Context, out chan<- Update) error {
	_ = ctx
	close(out)
	return errors.New("ebpf resolver: only supported on Linux")
}

// Close satisfies the Closer aspect of the resolver.
func (*EBPFResolver) Close() error {
	return nil
}
