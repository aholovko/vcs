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
	"62w2O/BLAAA=",
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