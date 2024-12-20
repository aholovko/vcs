// Package spec provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.11.0 DO NOT EDIT.
package spec

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	externalRef0 "github.com/trustbloc/vcs/pkg/restapi/v1/common"
)

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %s", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	var res = make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	pathPrefix := path.Dir(pathToFile)

	for rawPath, rawFunc := range externalRef0.PathToRawSpec(path.Join(pathPrefix, "./common.yaml")) {
		if _, ok := res[rawPath]; ok {
			// it is not possible to compare functions in golang, so always overwrite the old value
		}
		res[rawPath] = rawFunc
	}
	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	var resolvePath = PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		var pathToFile = url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
