package haproxy

import (
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) readOpts(_ ctx, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := b.verify(req); err != nil {
		return nil, err
	}

	if len(b.options) == 0 {
		return logical.ErrorResponse("No value at %v%v", req.MountPoint, req.Path), nil
	}

	resp := &logical.Response{
		Data: b.options,
	}
	return resp, nil
}

func (b *backend) createOpts(_ ctx, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := b.verify(req); err != nil {
		return nil, err
	}

	b.options["output"] = data.Get("output")

	if url := data.Get("remote").(string); url != "" {
		b.options["remote"] = url
		b.options["local"] = ""
		b.options["output"] = false
	}
	if file := data.Get("local").(string); file != "" {
		b.options["remote"] = ""
		b.options["local"] = file
		b.options["output"] = false
	}
	if crypter := data.Get("crypter").(string); crypter != "" {
		b.options["crypter"] = crypter
	}

	b.options["salt"] = data.Get("salt")
	return nil, nil
}

func (b *backend) deleteOpts(_ ctx, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := b.verify(req); err != nil {
		return nil, err
	}

	// Remove entry for specified path
	delete(b.options, fmt.Sprintf("%s/%s", req.ClientToken, req.Path))
	return nil, nil
}
