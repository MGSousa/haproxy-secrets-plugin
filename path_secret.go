package haproxy

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) readSecret(_ ctx, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := b.verify(req); err != nil {
		return nil, err
	}

	path := data.Get("path").(string)

	// decode the data
	var rawData map[string]interface{}
	fetchedData := b.store[fmt.Sprintf("%s/%s", req.ClientToken, path)]
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

func (b *backend) writeSecret(_ ctx, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := b.verify(req); err != nil {
		return nil, err
	}
	if len(b.options) == 0 {
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

		if url := b.options["remote"].(string); url != "" {
			// download HAProxy userlist
			response, err := http.Get(url)
			if err != nil {
				return nil, fmt.Errorf("failed to download HAProxy userlist: %s", err)
			}
			defer response.Body.Close()

			// read file contents from buffer
			if rawConfig, err = ioutil.ReadAll(response.Body); err != nil {
				return nil, fmt.Errorf("failed to read HAProxy config: %s", err)
			}

		} else if file := b.options["local"].(string); file != "" {
			// read file contents from file
			if rawConfig, err = ioutil.ReadFile(file); err != nil {
				return nil, fmt.Errorf("failed to read HAProxy config: %s", err)
			}
		}

		// parse password field
		config := string(rawConfig)
		securePass := "password "
		pos := strings.LastIndex(config, securePass)
		if pos == -1 {
			return nil, fmt.Errorf("failed to get HAProxy password: Is empty")
		}
		adjustedPos := pos + len(securePass)
		if adjustedPos >= len(config) {
			return nil, fmt.Errorf("failed to parse HAProxy userlist")
		}

		// save file temporary
		if err := ioutil.WriteFile("userlist.cfg",
			[]byte(strings.ReplaceAll(config, config[adjustedPos:],
				fmt.Sprintf("%s", hash))), 0777); err != nil {
			return nil, fmt.Errorf("failed to set HAProxy password: %s", err)
		}
	}

	// Store kv pairs in map at specified path
	b.store[fmt.Sprintf("%s/%s", req.ClientToken, path)] = buf

	var resp *logical.Response
	if b.options["output"].(bool) {
		resp = &logical.Response{
			Data: map[string]interface{}{"token": hash},
		}
	}

	return resp, nil
}

func (b *backend) deleteSecret(_ ctx, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := b.verify(req); err != nil {
		return nil, err
	}

	path := data.Get("path").(string)

	// Remove entry for specified path
	delete(b.store, fmt.Sprintf("%s/%s", req.ClientToken, path))
	return nil, nil
}
