/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package file

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"

	"github.com/google/uuid"
	"github.com/hashicorp/go-version"
	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/cmdutil-go/pkg/utils/cmd" //nolint:typecheck
	"github.com/trustbloc/did-go/method/jwk"
	"github.com/trustbloc/did-go/method/key"
	vdrpkg "github.com/trustbloc/did-go/vdr"
	"github.com/trustbloc/logutil-go/pkg/log" //nolint:typecheck
	longform "github.com/trustbloc/sidetree-go/pkg/vdr/sidetreelongform"

	"github.com/trustbloc/vcs/internal/logfields"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

const (
	commonEnvVarUsageText = "Alternatively, this can be set with the following environment variable: "

	profilesFilePathFlagName  = "profiles-file-path"
	profilesFilePathFlagUsage = "Profiles json file path." + commonEnvVarUsageText + profilesFilePathEnvKey
	profilesFilePathEnvKey    = "VC_REST_PROFILES_FILE_PATH"
)

var logger = log.New("vc-rest")

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config contain config.
type Config struct {
	KMSRegistry *vcskms.Registry
	TLSConfig   *tls.Config
	CMD         *cobra.Command
	HTTPClient  httpClient
}

// IssuerReader read issuer profiles.
type IssuerReader struct {
	issuers map[string]*profileapi.Issuer
}

// VerifierReader read verifier profiles.
type VerifierReader struct {
	verifiers map[string]*profileapi.Verifier
}

type profileData struct {
	IssuersData   []*issuerProfile   `json:"issuers"`
	VerifiersData []*verifierProfile `json:"verifiers"`
}

type issuerProfile struct {
	Data                *profileapi.Issuer `json:"issuer,omitempty"`
	CreateDID           bool               `json:"createDID"`
	DidDomain           string             `json:"didDomain"`
	DidServiceAuthToken string             `json:"didServiceAuthToken"`
}

type verifierProfile struct {
	Data                *profileapi.Verifier `json:"verifier,omitempty"`
	CreateDID           bool                 `json:"createDID"`
	DidDomain           string               `json:"didDomain"`
	DidServiceAuthToken string               `json:"didServiceAuthToken"`
}

// NewIssuerReader creates issuer Reader.
func NewIssuerReader(config *Config) (*IssuerReader, error) {
	profileJSONFile, err := cmdutils.GetUserSetVarFromString(config.CMD, profilesFilePathFlagName,
		profilesFilePathEnvKey, false)
	if err != nil {
		return nil, err
	}

	r := IssuerReader{issuers: make(map[string]*profileapi.Issuer)}

	jsonBytes, err := os.ReadFile(filepath.Clean(profileJSONFile))
	if err != nil {
		return nil, err
	}

	var p profileData
	if err = json.Unmarshal(jsonBytes, &p); err != nil {
		return nil, err
	}

	issuerProfiles := map[profileVersionKey]*profileapi.Issuer{}
	issuerProfileVersions := map[string]version.Collection{}

	for _, v := range p.IssuersData {
		v.Data.GroupID = uuid.NewString()

		if v.CreateDID {
			v.Data.SigningDID, err = createDid(v.DidDomain, v.DidServiceAuthToken, v.Data.KMSConfig, v.Data.WebHook,
				config, nil, v.Data.VCConfig)
			if err != nil {
				return nil, fmt.Errorf("issuer profile service: create profile failed: %w", err)
			}
		}

		logger.Info("create issuer profile successfully", log.WithID(v.Data.ID))

		// Set version as it come.
		r.issuers[fmt.Sprintf("%s_%s", v.Data.ID, v.Data.Version)] = v.Data

		issuerVersion := version.Must(version.NewVersion(v.Data.Version))

		createdIssuers[v.Data.ID] = v.Data
		issuerProfileVersions[v.Data.ID] = append(issuerProfileVersions[v.Data.ID], issuerVersion)
		issuerProfiles[getProfileVersionKey(v.Data.ID, issuerVersion)] = v.Data

		for _, ct := range v.Data.CredentialTemplates {
			if err := populateJSONSchemaID(ct); err != nil {
				logger.Error("Error populating JSON schema ID", log.WithError(err),
					logfields.WithProfileID(v.Data.ID), logfields.WithCredentialTemplateID(ct.ID))

				return nil, fmt.Errorf("credential template schema error: %w", err)
			}
		}
	}

	populateLatestTag(issuerProfileVersions, issuerProfiles, r.issuers)

	return &r, nil
}

// GetProfile returns profile with given id.
func (p *IssuerReader) GetProfile(
	profileID profileapi.ID, profileVersion profileapi.Version) (*profileapi.Issuer, error) {
	profile, ok := p.issuers[fmt.Sprintf("%s_%s", profileID, profileVersion)]
	if !ok {
		return nil, resterr.ErrProfileNotFound
	}

	if !profile.Active {
		return nil, resterr.ErrProfileInactive
	}

	// Check latest version of given profileID if it is inactive.
	latestProfileVersion, ok := p.issuers[fmt.Sprintf("%s_%s", profileID, latest)]
	if !ok {
		return nil, resterr.ErrProfileNotFound
	}

	if !latestProfileVersion.Active {
		return nil, resterr.ErrProfileInactive
	}

	b, err := json.Marshal(profile) // nolint:staticcheck
	if err != nil {
		return nil, fmt.Errorf("marshal profile: %w", err)
	}

	var cloned profileapi.Issuer
	if err = json.Unmarshal(b, &cloned); err != nil {
		return nil, fmt.Errorf("unmarshal profile: %w", err)
	}

	return &cloned, nil
}

// GetAllProfiles returns all profiles with given organization id.
func (p *IssuerReader) GetAllProfiles(_ string) ([]*profileapi.Issuer, error) {
	return nil, nil
}

// NewVerifierReader creates verifier Reader.
func NewVerifierReader(config *Config) (*VerifierReader, error) {
	profileJSONFile, err := cmdutils.GetUserSetVarFromString(config.CMD, profilesFilePathFlagName,
		profilesFilePathEnvKey, false)
	if err != nil {
		return nil, err
	}

	r := VerifierReader{
		verifiers: make(map[string]*profileapi.Verifier),
	}

	jsonBytes, err := os.ReadFile(filepath.Clean(profileJSONFile))
	if err != nil {
		return nil, err
	}

	var p profileData
	if err = json.Unmarshal(jsonBytes, &p); err != nil {
		return nil, err
	}

	verifierProfiles := map[profileVersionKey]*profileapi.Verifier{}
	verifierProfileVersions := map[string]version.Collection{}

	for _, v := range p.VerifiersData {
		if v.Data.OIDCConfig != nil && v.CreateDID {
			v.Data.SigningDID, err = createDid(v.DidDomain, v.DidServiceAuthToken, v.Data.KMSConfig, v.Data.WebHook,
				config, v.Data.OIDCConfig, nil)
			if err != nil {
				return nil, fmt.Errorf("verifier profile service: create profile failed: %w", err)
			}
		}

		logger.Info("create verifier profile successfully", log.WithID(v.Data.ID))

		r.setTrustList(v.Data)
		// Set version as it come.
		r.verifiers[fmt.Sprintf("%s_%s", v.Data.ID, v.Data.Version)] = v.Data

		verifierVersion := version.Must(version.NewVersion(v.Data.Version))

		verifierProfileVersions[v.Data.ID] = append(verifierProfileVersions[v.Data.ID], verifierVersion)
		verifierProfiles[getProfileVersionKey(v.Data.ID, verifierVersion)] = v.Data
	}

	populateLatestTag(verifierProfileVersions, verifierProfiles, r.verifiers)

	return &r, nil
}

func (p *VerifierReader) setTrustList(
	verifier *profileapi.Verifier,
) {
	if verifier == nil || verifier.Checks == nil || len(createdIssuers) == 0 ||
		len(verifier.Checks.Credential.IssuerTrustList) == 0 {
		return
	}

	updated := make(map[string]profileapi.TrustList)
	for k, v := range verifier.Checks.Credential.IssuerTrustList {
		issuer, ok := createdIssuers[k]
		if !ok {
			continue
		}

		updated[issuer.SigningDID.DID] = v
	}

	verifier.Checks.Credential.IssuerTrustList = updated
}

// GetProfile returns profile with given id.
func (p *VerifierReader) GetProfile(
	profileID profileapi.ID, profileVersion profileapi.Version) (*profileapi.Verifier, error) {
	profile, ok := p.verifiers[fmt.Sprintf("%s_%s", profileID, profileVersion)]
	if !ok {
		return nil, resterr.ErrProfileNotFound
	}

	if !profile.Active {
		return nil, resterr.ErrProfileInactive
	}

	// Check latest version of given profileID if it is inactive.
	latestProfileVersion, ok := p.verifiers[fmt.Sprintf("%s_%s", profileID, latest)]
	if !ok {
		return nil, resterr.ErrProfileNotFound
	}

	if !latestProfileVersion.Active {
		return nil, resterr.ErrProfileInactive
	}

	return profile, nil
}

// GetAllProfiles returns all profiles with given organization id.
func (p *verifierProfile) GetAllProfiles(_ string) ([]*profileapi.Verifier, error) {
	return nil, nil
}

// AddFlags add flags in cmd.
func AddFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(profilesFilePathFlagName, "", "", profilesFilePathFlagUsage)
}

func getDifDIDOrigin(webHook string) (string, error) {
	difDIDOrigin := ""
	if webHook != "" {
		var u *url.URL

		u, err := url.Parse(webHook)
		if err != nil {
			return "", err
		}

		difDIDOrigin = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	}
	return difDIDOrigin, nil
}

func createDid(
	didDomain string,
	_ string,
	kmsConfig *vcskms.Config,
	webHook string,
	config *Config,
	oidcConfig *profileapi.OIDC4VPConfig,
	vcConfig *profileapi.VCConfig,
) (*profileapi.SigningDID, error) {
	if oidcConfig == nil && vcConfig == nil {
		return nil, fmt.Errorf("create did: either oidcConfig or vcConfig must be provided")
	}

	lf, err := longform.New()
	if err != nil {
		return nil, err
	}

	didCreator := newCreator(&creatorConfig{
		vdr: vdrpkg.New(vdrpkg.WithVDR(lf), vdrpkg.WithVDR(jwk.New()), vdrpkg.WithVDR(key.New())),
	})

	keyCreator, err := config.KMSRegistry.GetKeyManager(kmsConfig)
	if err != nil {
		return nil, fmt.Errorf("get keyCreator %w", err)
	}

	difDIDOrigin, err := getDifDIDOrigin(webHook)
	if err != nil {
		return nil, fmt.Errorf("get difDidOrigin %w", err)
	}

	var createResult *createResult
	if oidcConfig != nil {
		createResult, err = didCreator.publicDID(oidcConfig.DIDMethod, oidcConfig.ROSigningAlgorithm,
			oidcConfig.KeyType, keyCreator, didDomain, difDIDOrigin)
		if err != nil {
			return nil, fmt.Errorf("create did %w", err)
		}
	} else {
		createResult, err = didCreator.publicDID(vcConfig.DIDMethod, vcConfig.SigningAlgorithm, vcConfig.KeyType,
			keyCreator, didDomain, difDIDOrigin)
		if err != nil {
			return nil, fmt.Errorf("create did %w", err)
		}
	}

	return &profileapi.SigningDID{
		DID:            createResult.didID,
		Creator:        createResult.creator,
		KMSKeyID:       createResult.kmsKeyID,
		UpdateKeyURL:   createResult.updateKeyURL,
		RecoveryKeyURL: createResult.recoveryKeyURL,
	}, nil
}

func populateJSONSchemaID(ct *profileapi.CredentialTemplate) error {
	if ct.JSONSchema == "" {
		logger.Debug("No JSON schema set for credential template", log.WithID(ct.ID))

		return nil
	}

	var doc map[string]interface{}

	err := json.Unmarshal([]byte(ct.JSONSchema), &doc)
	if err != nil {
		return fmt.Errorf("unmarshal JSON schema: %w", err)
	}

	schemaIDObj, ok := doc["$id"]
	if !ok {
		return fmt.Errorf("missing $id field in JSON schema")
	}

	schemaID, ok := schemaIDObj.(string)
	if !ok {
		return fmt.Errorf("expecting field '$id' in JSON schema to be a string type but was %s",
			reflect.TypeOf(schemaIDObj))
	}

	ct.JSONSchemaID = schemaID

	logger.Info("Populated credential template with JSON schema ID", logfields.WithCredentialTemplateID(ct.ID),
		logfields.WithJSONSchemaID(ct.JSONSchemaID))

	return nil
}
