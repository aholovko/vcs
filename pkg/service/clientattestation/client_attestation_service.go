/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination client_attestation_service_mocks_test.go -package clientattestation_test -source=client_attestation_service.go -mock_names httpClient=MockHTTPClient,vcStatusVerifier=MockVCStatusVerifier

package clientattestation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/verifiable"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

const WalletAttestationVCType = "WalletAttestationCredential"

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type vcStatusVerifier interface {
	ValidateVCStatus(ctx context.Context, vcStatus *verifiable.TypedID, issuer *verifiable.Issuer) error
}

// Config defines configuration for Service.
type Config struct {
	HTTPClient       httpClient
	DocumentLoader   ld.DocumentLoader
	ProofChecker     verifiable.CombinedProofChecker
	VCStatusVerifier vcStatusVerifier
}

// Service implements attestation functionality for OAuth 2.0 Attestation-Based Client Authentication.
type Service struct {
	httpClient       httpClient
	documentLoader   ld.DocumentLoader
	proofChecker     verifiable.CombinedProofChecker
	vcStatusVerifier vcStatusVerifier
}

// NewService returns a new Service instance.
func NewService(config *Config) *Service {
	return &Service{
		httpClient:       config.HTTPClient,
		documentLoader:   config.DocumentLoader,
		proofChecker:     config.ProofChecker,
		vcStatusVerifier: config.VCStatusVerifier,
	}
}

// ValidateIssuance validates attestation VP and requests issuance policy evaluation.
func (s *Service) ValidateIssuance(
	ctx context.Context,
	profile *profileapi.Issuer,
	jwtVP string,
) error {
	_, attestationVCs, err := s.validateAttestationVP(ctx, jwtVP)
	if err != nil {
		return err
	}

	if profile.Policy.URL == "" {
		return nil
	}

	req := &IssuancePolicyEvaluationRequest{
		IssuerDID: profile.SigningDID.DID,
	}

	req.AttestationVC = make([]string, len(attestationVCs))

	for i, vc := range attestationVCs {
		jwtVC, convertErr := vc.ToJWTString()
		if convertErr != nil {
			return fmt.Errorf("convert attestation vc to jwt: %w", convertErr)
		}

		req.AttestationVC[i] = jwtVC
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := s.requestPolicyEvaluation(ctx, profile.Policy.URL, payload)
	if err != nil {
		return fmt.Errorf("policy evaluation: %w", err)
	}

	if !resp.Allowed {
		return ErrInteractionRestricted
	}

	return nil
}

// ValidatePresentation validates attestation VP and requests presentation policy evaluation.
func (s *Service) ValidatePresentation(
	ctx context.Context,
	profile *profileapi.Verifier,
	jwtVP string,
) error {
	vp, attestationVCs, err := s.validateAttestationVP(ctx, jwtVP)
	if err != nil {
		return err
	}

	if profile.Policy.URL == "" {
		return nil
	}

	req := &PresentationPolicyEvaluationRequest{
		VerifierDID: profile.SigningDID.DID,
	}

	req.AttestationVC = make([]string, len(attestationVCs))

	for i, vc := range attestationVCs {
		jwtVC, marshalErr := vc.ToJWTString()
		if marshalErr != nil {
			return fmt.Errorf("marshal attestation vc to jwt: %w", marshalErr)
		}

		req.AttestationVC[i] = jwtVC
	}

	credentialMetadata := make([]*CredentialMetadata, 0)

	for _, vc := range vp.Credentials() {
		if lo.Contains(vc.Contents().Types, WalletAttestationVCType) {
			continue
		}

		vcc := vc.Contents()

		var iss, exp string

		if vcc.Issued != nil {
			iss = vcc.Issued.FormatToString()
		}

		if vcc.Expired != nil {
			exp = vcc.Expired.FormatToString()
		}

		credentialMetadata = append(credentialMetadata, &CredentialMetadata{
			CredentialID: vcc.ID,
			Types:        vcc.Types,
			IssuerID:     vcc.Issuer.ID,
			Issued:       iss,
			Expired:      exp,
		})
	}

	if len(credentialMetadata) > 0 {
		req.CredentialMetadata = credentialMetadata
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := s.requestPolicyEvaluation(ctx, profile.Policy.URL, payload)
	if err != nil {
		return fmt.Errorf("policy evaluation: %w", err)
	}

	if !resp.Allowed {
		return ErrInteractionRestricted
	}

	return nil
}

func (s *Service) validateAttestationVP(
	ctx context.Context,
	jwtVP string,
) (*verifiable.Presentation, []*verifiable.Credential, error) {
	attestationVP, err := verifiable.ParsePresentation(
		[]byte(jwtVP),
		// The verification of proof is conducted manually, along with an extra verification to ensure that signer of
		// the VP matches the subject of the attestation VC.
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(s.documentLoader),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("parse attestation vp: %w", err)
	}

	attestationVCs := make([]*verifiable.Credential, 0)

	for _, vc := range attestationVP.Credentials() {
		if !lo.Contains(vc.Contents().Types, WalletAttestationVCType) {
			continue
		}

		// validate attestation VC
		credentialOpts := []verifiable.CredentialOpt{
			verifiable.WithProofChecker(s.proofChecker),
			verifiable.WithJSONLDDocumentLoader(s.documentLoader),
		}

		if err = vc.ValidateCredential(credentialOpts...); err != nil {
			return nil, nil, fmt.Errorf("validate attestation vc: %w", err)
		}

		if err = vc.CheckProof(credentialOpts...); err != nil {
			return nil, nil, fmt.Errorf("check attestation vc proof: %w", err)
		}

		vcc := vc.Contents()

		if vcc.Expired != nil && time.Now().UTC().After(vcc.Expired.Time) {
			return nil, nil, fmt.Errorf("attestation vc is expired")
		}

		// validate vp proof with extra check for wallet binding
		if err = jwt.CheckProof(jwtVP, s.proofChecker, &vcc.Subject[0].ID, nil); err != nil {
			return nil, nil, fmt.Errorf("check attestation vp proof: %w", err)
		}

		// check attestation VC status
		if err = s.vcStatusVerifier.ValidateVCStatus(ctx, vcc.Status, vcc.Issuer); err != nil {
			return nil, nil, fmt.Errorf("validate attestation vc status: %w", err)
		}

		attestationVCs = append(attestationVCs, vc)
	}

	if len(attestationVCs) == 0 {
		return nil, nil, errors.New("no attestation vc found")
	}

	return attestationVP, attestationVCs, nil
}

func (s *Service) requestPolicyEvaluation(
	ctx context.Context,
	policyURL string,
	payload []byte,
) (*PolicyEvaluationResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, policyURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Add("content-type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result *PolicyEvaluationResponse

	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return result, nil
}
