package haproxy

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) readOpts(ctx ctx, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := b.verifyClient(req); err != nil {
		return nil, err
	}

	// return data from persistence storage
	if err, _ := b.readConfigStorage(ctx, req.Storage); err != nil {
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

func (b *backend) setOpts(ctx ctx, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := b.verifyClient(req); err != nil {
		return nil, err
	}

	// validates request schema
	if err := validateSchema(req, data); err != nil {
		return nil, err
	}

	b.options["output"] = data.Get("output")

	if url := data.Get("remote_path").(string); url != "" {
		b.options["remote_path"] = url
		b.options["source_path"] = ""
		b.options["output"] = false
	}
	if file := data.Get("source_path").(string); file != "" {
		b.options["remote_path"] = ""
		b.options["source_path"] = file
		b.options["output"] = false
	}
	if crypter := data.Get("crypter").(string); crypter != "" {
		b.options["crypter"] = crypter
	}

	b.options["persist"] = data.Get("persist")
	b.options["target_path"] = data.Get("target_path")

	// always persist data options
	if err := b.setConfigStorage(ctx, req.Storage); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) deleteOpts(ctx ctx, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := b.verifyClient(req); err != nil {
		return nil, err
	}

	// validates request schema
	if err := validateSchema(req, data); err != nil {
		return nil, err
	}

	// check if is to remove specified field
	field := data.Get("field").(string)
	if field == "" {

		// remove persisted storage, if not exists ignores it
		if err := b.deleteConfigStorage(ctx, req.Storage); err != nil {
			return nil, err
		}
	} else {

		// remove entry for specified path
		delete(b.options, field)
		if err := b.setConfigStorage(ctx, req.Storage); err != nil {
			return nil, err
		}
	}
	return nil, nil
}
