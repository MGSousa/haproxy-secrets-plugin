package haproxy

import (
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) readSecret(ctx ctx, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := b.verifyClient(req); err != nil {
		return nil, err
	}

	path := data.Get("path").(string)

	// return secret data from persistence storage
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		if err := entry.DecodeJSON(&b.kv); err != nil {
			return nil, err
		}
	}

	// decode the data
	var rawData map[string]interface{}
	fetchedData := b.kv[fmt.Sprintf("%s/%s", req.ClientToken, path)]
	if fetchedData == nil {
		resp := logical.ErrorResponse("No value at %v%v", req.MountPoint, req.Path)
		return resp, nil
	}

	if err := jsonutil.DecodeJSON(fetchedData, &rawData); err != nil {
		return nil, fmt.Errorf("json decoding failed: %s", err)
	}

	// generate the response
	resp := &logical.Response{
		Data: rawData,
	}
	return resp, nil
}

func (b *backend) writeSecret(ctx ctx, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := b.verifyClient(req); err != nil {
		return nil, err
	}

	if err, ok := b.readConfigStorage(ctx, req.Storage); err != nil || !ok {
		return nil, fmt.Errorf("haproxy options must be provided")
	}

	// check to make sure that kv pairs provided
	if len(req.Data) == 0 {
		return nil, fmt.Errorf("data must be provided to store in secret")
	}
	path := data.Get("path").(string)

	// JSON encode the data
	buf, err := jsonutil.EncodeJSON(req.Data)
	if err != nil {
		return nil, fmt.Errorf("json encoding failed: %s", err)
	}

	// generate hash from the data value
	hash, err := generateHash(b.options["crypter"].(string), req)
	if err != nil {
		return nil, err
	}

	// check if custom options is not empty
	if !b.options["output"].(bool) {
		var rawConfig []byte

		// read file contents from remote or local
		if url := b.options["remote_path"].(string); url != "" {
			if rawConfig, err = readFile(url, true); err != nil {
				return nil, err
			}

		} else if file := b.options["source_path"].(string); file != "" {
			if rawConfig, err = readFile(url, false); err != nil {
				return nil, err
			}
		}

		// parse password field
		if err = parseFile(string(rawConfig), hash, b.options["target_path"].(string)); err != nil {
			return nil, err
		}
	}

	// store kv pairs in map at specified path
	b.kv[fmt.Sprintf("%s/%s", req.ClientToken, path)] = buf

	// store kv to persistence storage
	if b.options["persist"].(bool) {
		entry, _ := logical.StorageEntryJSON(path, &b.kv)
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, fmt.Errorf("cannot persist data: %s", err)
		}
	}

	var resp *logical.Response
	if b.options["output"].(bool) {
		resp = &logical.Response{
			Data: map[string]interface{}{"token": hash},
		}
	}

	return resp, nil
}

func (b *backend) deleteSecret(ctx ctx, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := b.verifyClient(req); err != nil {
		return nil, err
	}

	path := data.Get("path").(string)

	// remove entry for specified path
	delete(b.kv, fmt.Sprintf("%s/%s", req.ClientToken, path))

	// remove persisted storage, if not exists ignores it
	if err := req.Storage.Delete(ctx, path); err != nil {
		return nil, fmt.Errorf("cannot remove persisted data: %s", err)
	}
	return nil, nil
}
