package haproxy

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	kvPattern      = "password"
	optionsPattern = "options"
)

// backend wraps the backend framework and adds a map for storing key value pairs
type backend struct {
	*framework.Backend

	kv      map[string][]byte
	options map[string]interface{}
}

var _ logical.Factory = Factory

// Factory configures and returns Mock backends
func Factory(ctx ctx, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend()
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func newBackend() (*backend, error) {
	b := &backend{
		kv:      make(map[string][]byte),
		options: make(map[string]interface{}),
	}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(haproxyHelp),
		BackendType: logical.TypeLogical,
		Paths: framework.PathAppend(
			b.paths(),
			b.args(),
		),
	}

	return b, nil
}

func (b *backend) paths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern:      kvPattern,
			HelpSynopsis: "Set the path of the secret for HAProxy",
			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Description: "Specifies the path of the secret.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.readSecret,
					Summary:  "Retrieve the secret from the map.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.writeSecret,
					Summary:  "Store a secret at the specified location.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.writeSecret,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.deleteSecret,
					Summary:  "Deletes the secret at the specified location.",
				},
			},
			ExistenceCheck: b.existenceCheck,
		},
	}
}

func (b *backend) args() []*framework.Path {
	return []*framework.Path{
		{
			Pattern:      optionsPattern,
			HelpSynopsis: "Set custom options for this plugin",
			Fields: map[string]*framework.FieldSchema{
				"output": {
					Type:        framework.TypeBool,
					Description: "Defines if secret hashed will be returned, ignores userlist options",
					Default:     true,
				},
				"remote_path": {
					Type:        framework.TypeString,
					Description: "Remote userlist file to parse from, if set ignores 'source_path'",
				},
				"source_path": {
					Type:        framework.TypeString,
					Description: "Userlist local file to parse from, use this if 'remote_path' not set",
				},
				"target_path": {
					Type:        framework.TypeString,
					Description: "Target file path where userlist will be saved",
				},
				"crypter": {
					Type:          framework.TypeString,
					Description:   "Algorithm to generate hashes",
					AllowedValues: []interface{}{"sha256", "sha512"},
					Default:       "sha256",
				},
				"persist": {
					Type:        framework.TypeBool,
					Description: "Persist data after seal/unseal",
					Default:     false,
				},
				"field": {
					Type:        framework.TypeString,
					Description: "Field reference on delete",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.readOpts,
					Summary:  "Retrieve available options.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.setOpts,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.setOpts,
					Summary:  "Set available options.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.deleteOpts,
					Summary:  "Remove all options",
				},
			},
		},
	}
}

func (b *backend) existenceCheck(ctx ctx, req *logical.Request, _ *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %s", err)
	}

	return out != nil, nil
}

func (b *backend) verifyClient(req *logical.Request) error {
	if req.ClientToken == "" {
		return fmt.Errorf("client token empty")
	}
	return nil
}

const haproxyHelp = `
The HAProxy backend is a secrets backend that stores KV pairs in a map then generates a hash for userlist config.
`
