// Package common provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.11.0 DO NOT EDIT.
package common

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Defines values for DIDMethod.
const (
	DIDMethodKey DIDMethod = "key"
	DIDMethodOrb DIDMethod = "orb"
	DIDMethodWeb DIDMethod = "web"
)

// Defines values for KMSConfigType.
const (
	KMSConfigTypeAws   KMSConfigType = "aws"
	KMSConfigTypeLocal KMSConfigType = "local"
	KMSConfigTypeWeb   KMSConfigType = "web"
)

// Defines values for VCFormat.
const (
	CwtVcLd     VCFormat = "cwt_vc-ld"
	JwtVcJson   VCFormat = "jwt_vc_json"
	JwtVcJsonLd VCFormat = "jwt_vc_json-ld"
	LdpVc       VCFormat = "ldp_vc"
)

// Defines values for VPFormat.
const (
	CwtVp VPFormat = "cwt_vp"
	JwtVp VPFormat = "jwt_vp"
	LdpVp VPFormat = "ldp_vp"
)

// Model to convey the details about the Credentials the Client wants to obtain.
type AuthorizationDetails struct {
	// REQUIRED when Format parameter is not present. String specifying a unique identifier of the Credential being described in the credential_configurations_supported map in the Credential Issuer Metadata. The referenced object in the credential_configurations_supported map conveys the details, such as the format, for issuance of the requested Credential. It MUST NOT be present if format parameter is present.
	CredentialConfigurationId *string `json:"credential_configuration_id,omitempty"`

	// Object containing the detailed description of the credential type.
	CredentialDefinition *CredentialDefinition `json:"credential_definition,omitempty"`

	// For Token response only. Array of strings, each uniquely identifying a Credential that can be issued using the Access Token returned in this response. Each of these Credentials corresponds to the same entry in the credential_configurations_supported Credential Issuer metadata but can contain different claim values or a different subset of claims within the claims set identified by that Credential type.
	CredentialIdentifiers *[]string `json:"credential_identifiers,omitempty"`

	// REQUIRED when CredentialConfigurationId parameter is not present. String identifying the format of the Credential the Wallet needs. This Credential format identifier determines further claims in the authorization details object needed to identify the Credential type in the requested format. It MUST NOT be present if credential_configuration_id parameter is present.
	Format *string `json:"format,omitempty"`

	// An array of strings that allows a client to specify the location of the resource server(s) allowing the Authorization Server to mint audience restricted access tokens.
	Locations *[]string `json:"locations,omitempty"`

	// String that determines the authorization details type. MUST be set to "openid_credential" for OIDC4VC.
	Type string `json:"type"`
}

// Object containing the detailed description of the credential type.
type CredentialDefinition struct {
	// For ldp_vc only. Array as defined in https://www.w3.org/TR/vc-data-model/#contexts.
	Context *[]string `json:"@context,omitempty"`

	// An object containing a list of name/value pairs, where each name identifies a claim offered in the Credential. The value can be another such object (nested data structures), or an array of such objects.
	CredentialSubject *map[string]interface{} `json:"credentialSubject,omitempty"`

	// Array designating the types a certain credential type supports
	Type []string `json:"type"`
}

// Model for credentials field from credential response.
type CredentialResponseCredentialObject struct {
	Credential interface{} `json:"credential"`
}

// DID method of the DID to be used for signing.
type DIDMethod string

// Model for KMS configuration.
type KMSConfig struct {
	// Prefix of database used by local kms.
	DbPrefix *string `json:"dbPrefix,omitempty"`

	// Type of database used by local kms.
	DbType *string `json:"dbType,omitempty"`

	// URL to database used by local kms.
	DbURL *string `json:"dbURL,omitempty"`

	// KMS endpoint.
	Endpoint *string `json:"endpoint,omitempty"`

	// Path to secret lock used by local kms.
	SecretLockKeyPath *string `json:"secretLockKeyPath,omitempty"`

	// Type of kms used to create and store DID keys.
	Type KMSConfigType `json:"type"`
}

// Type of kms used to create and store DID keys.
type KMSConfigType string

// Supported VC formats.
type VCFormat string

// Supported VP formats.
type VPFormat string

// WalletInitiatedFlowData defines model for WalletInitiatedFlowData.
type WalletInitiatedFlowData struct {
	ClaimEndpoint        string    `json:"claim_endpoint"`
	CredentialTemplateId string    `json:"credential_template_id"`
	OpState              string    `json:"op_state"`
	ProfileId            string    `json:"profile_id"`
	ProfileVersion       string    `json:"profile_version"`
	Scopes               *[]string `json:"scopes"`
}

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
	"wfz8XwAAAP//TheT4mMTAAA=",
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
