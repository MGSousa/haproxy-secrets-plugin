package haproxy

import (
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) readConfigStorage(ctx ctx, req logical.Storage) (err error, ok bool) {
	entry, err := req.Get(ctx, optionsPattern)
	if err != nil {
		return
	}
	if entry != nil {
		ok = true
		if err := entry.DecodeJSON(&b.options); err != nil {
			return err, ok
		}
	}
	return
}

func (b *backend) setConfigStorage(ctx ctx, req logical.Storage) error {
	entry, err := logical.StorageEntryJSON(optionsPattern, &b.options)
	if err != nil {
		return err
	}
	if err := req.Put(ctx, entry); err != nil {
		return fmt.Errorf("cannot persist data: %s", err)
	}
	return nil
}

func (b *backend) deleteConfigStorage(ctx ctx, req logical.Storage) error {
	if err := req.Delete(ctx, optionsPattern); err != nil {
		return fmt.Errorf("cannot remove persisted data: %s", err)
	}

	b.options = map[string]interface{}{}
	return nil
}
