package haproxy

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func validateSchema(req *logical.Request, data *framework.FieldData) error {
	var unknownFields []string
	for k := range req.Data {
		// check if each field is valid
		if _, ok := data.Schema[k]; !ok {
			unknownFields = append(unknownFields, k)
		}
	}

	if len(unknownFields) > 0 {
		return fmt.Errorf("unknown fields: %q", unknownFields)
	}
	return nil
}

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

func readFile(file string, remote bool) (rawConfig []byte, err error) {
	if remote {
		response, err := http.Get(file)
		if err != nil {
			return nil, fmt.Errorf("failed to download HAProxy userlist: %s", err)
		}
		defer response.Body.Close()

		// read file contents from buffer
		if rawConfig, err = ioutil.ReadAll(response.Body); err != nil {
			return nil, fmt.Errorf("failed to read HAProxy config: %s", err)
		}
	} else {
		if rawConfig, err = ioutil.ReadFile(file); err != nil {
			return nil, fmt.Errorf("failed to read HAProxy config: %s", err)
		}
	}
	return
}

func parseFile(config, hash, path string) error {
	securePass := "password "
	pos := strings.LastIndex(config, securePass)
	if pos == -1 {
		return fmt.Errorf("failed to get HAProxy password: Is empty")
	}
	adjustedPos := pos + len(securePass)
	if adjustedPos >= len(config) {
		return fmt.Errorf("failed to parse HAProxy userlist")
	}

	// save file in final path
	if err := ioutil.WriteFile(path,
		[]byte(strings.ReplaceAll(config, config[adjustedPos:],
			fmt.Sprintf("%s", hash))), 0777); err != nil {
		return fmt.Errorf("failed to set HAProxy password: %s", err)
	}
	return nil
}
