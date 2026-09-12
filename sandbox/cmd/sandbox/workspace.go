package main

import (
	"context"

	"tinfoil/internal/volume"
)

const (
	workspace = "/workspace"
	home      = workspace + "/home"
	profile   = "/nix/var/nix/profiles/default"
)

func (s *sandbox) open(ctx context.Context, key []byte, owner, token string) error {
	return (volume.Client{}).Enroll(ctx, s.workspace, volume.Request{Key: key, Binding: []byte(owner), Permit: token})
}
