package haproxy

import (
	"fmt"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/hashicorp/vault/sdk/logical"
)

func generateHash(crypter string, req *logical.Request) (hash string, err error) {
	var c crypt.Crypter
	switch crypter {
	case "sha256":
		c = crypt.New(crypt.SHA256)
	case "sha512":
		c = crypt.New(crypt.SHA512)
	default:
		return "", fmt.Errorf("no crypter algorithm found")
	}

	for _, v := range req.Data {
		// encrypt the data value
		if hash, err = c.Generate([]byte(v.(string)), nil); err != nil {
			return "", fmt.Errorf("generating hash failed: %s", err)
		}
		break
	}
	return hash, nil
}
