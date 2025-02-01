// Package common provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.4.1 DO NOT EDIT.
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

// AuthorizationDetails Model to convey the details about the Credentials the Client wants to obtain.
type AuthorizationDetails struct {
	// CredentialConfigurationId REQUIRED when Format parameter is not present. String specifying a unique identifier of the Credential being described in the credential_configurations_supported map in the Credential Issuer Metadata. The referenced object in the credential_configurations_supported map conveys the details, such as the format, for issuance of the requested Credential. It MUST NOT be present if format parameter is present.
	CredentialConfigurationId *string `json:"credential_configuration_id,omitempty"`

	// CredentialDefinition Object containing the detailed description of the credential type.
	CredentialDefinition *CredentialDefinition `json:"credential_definition,omitempty"`

	// CredentialIdentifiers For Token response only. Array of strings, each uniquely identifying a Credential that can be issued using the Access Token returned in this response. Each of these Credentials corresponds to the same entry in the credential_configurations_supported Credential Issuer metadata but can contain different claim values or a different subset of claims within the claims set identified by that Credential type.
	CredentialIdentifiers *[]string `json:"credential_identifiers,omitempty"`

	// Format REQUIRED when CredentialConfigurationId parameter is not present. String identifying the format of the Credential the Wallet needs. This Credential format identifier determines further claims in the authorization details object needed to identify the Credential type in the requested format. It MUST NOT be present if credential_configuration_id parameter is present.
	Format *string `json:"format,omitempty"`

	// Locations An array of strings that allows a client to specify the location of the resource server(s) allowing the Authorization Server to mint audience restricted access tokens.
	Locations *[]string `json:"locations,omitempty"`

	// Type String that determines the authorization details type. MUST be set to "openid_credential" for OIDC4VC.
	Type string `json:"type"`
}

// CredentialDefinition Object containing the detailed description of the credential type.
type CredentialDefinition struct {
	// Context For ldp_vc only. Array as defined in https://www.w3.org/TR/vc-data-model/#contexts.
	Context *[]string `json:"@context,omitempty"`

	// CredentialSubject An object containing a list of name/value pairs, where each name identifies a claim offered in the Credential. The value can be another such object (nested data structures), or an array of such objects.
	CredentialSubject *map[string]interface{} `json:"credentialSubject,omitempty"`

	// Type Array designating the types a certain credential type supports
	Type []string `json:"type"`
}

// CredentialResponseCredentialObject Model for credentials field from credential response.
type CredentialResponseCredentialObject struct {
	Credential any `json:"credential"`
}

// DIDMethod DID method of the DID to be used for signing.
type DIDMethod string

// KMSConfig Model for KMS configuration.
type KMSConfig struct {
	// DbPrefix Prefix of database used by local kms.
	DbPrefix *string `json:"dbPrefix,omitempty"`

	// DbType Type of database used by local kms.
	DbType *string `json:"dbType,omitempty"`

	// DbURL URL to database used by local kms.
	DbURL *string `json:"dbURL,omitempty"`

	// Endpoint KMS endpoint.
	Endpoint *string `json:"endpoint,omitempty"`

	// SecretLockKeyPath Path to secret lock used by local kms.
	SecretLockKeyPath *string `json:"secretLockKeyPath,omitempty"`

	// Type Type of kms used to create and store DID keys.
	Type KMSConfigType `json:"type"`
}

// KMSConfigType Type of kms used to create and store DID keys.
type KMSConfigType string

// PrivateAPIErrorResponse Model for private API error response.
type PrivateAPIErrorResponse struct {
	Component *string `json:"component,omitempty"`

	// Error Error code.
	Error            string  `json:"error"`
	ErrorDescription *string `json:"error_description,omitempty"`
	HttpStatus       *int    `json:"http_status,omitempty"`
	IncorrectValue   *string `json:"incorrect_value,omitempty"`
	Operation        *string `json:"operation,omitempty"`
}

// PublicAPIErrorResponse Model for public API error response.
type PublicAPIErrorResponse struct {
	// Error Error code.
	Error            string  `json:"error"`
	ErrorDescription *string `json:"error_description,omitempty"`
}

// VCFormat Supported VC formats.
type VCFormat string

// VPFormat Supported VP formats.
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
	"P/4XAAD//00+JpD7FQAA",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
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
	res := make(map[string]func() ([]byte, error))
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
	resolvePath := PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		pathToFile := url.String()
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
