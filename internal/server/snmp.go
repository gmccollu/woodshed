package server

import (
	"context"

	"github.com/gmccollu/woodshed/internal/api"
)

// The SNMP trap receiver's backend methods (api.SNMPBackend).

func (b *backend) SNMP(ctx context.Context) (api.SNMPState, error) { return api.SNMPState{}, nil }

func (b *backend) ReloadMIBs(ctx context.Context) (api.SNMPMIBs, error) { return api.SNMPMIBs{}, nil }

func (b *backend) SNMPFailures(ctx context.Context) ([]api.SNMPFailure, error) { return nil, nil }

func (b *backend) SNMPUsers(ctx context.Context) ([]api.SNMPUser, error) { return nil, nil }

func (b *backend) CreateSNMPUser(ctx context.Context, in api.SNMPUserInput) (api.SNMPUser, error) {
	return api.SNMPUser{}, api.ErrNotFound
}

func (b *backend) UpdateSNMPUser(ctx context.Context, name string, in api.SNMPUserInput) (api.SNMPUser, error) {
	return api.SNMPUser{}, api.ErrNotFound
}

func (b *backend) DeleteSNMPUser(ctx context.Context, name string) error { return api.ErrNotFound }
