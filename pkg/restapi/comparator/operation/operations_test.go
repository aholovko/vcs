/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/edge-service/pkg/client/csh/models"
	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation"
	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation/openapi"
	"github.com/trustbloc/edge-service/pkg/restapi/vault"
)

func Test_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			chs := newAgent(t)
			chsZCAP := newZCAP(t, chs, chs)
			p := models.Profile{Zcap: compress(t, marshal(t, chsZCAP))}
			b, err := p.MarshalBinary()
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		op, err := operation.New(&operation.Config{CSHBaseURL: serv.URL, StoreProvider: &mockstorage.MockStoreProvider{
			Store: s}, KeyManager: &mockkms.KeyManager{}, VDR: &vdr.MockVDRegistry{
			CreateFunc: func(s string, doc *did.Doc, option ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return &did.DocResolution{DIDDocument: &did.Doc{ID: "did:ex:123"}}, nil
			}}})
		require.NoError(t, err)
		require.NotNil(t, op)

		require.Equal(t, 4, len(op.GetRESTHandlers()))
	})

	t.Run("test failed to create profile from csh", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		_, err := operation.New(&operation.Config{CSHBaseURL: serv.URL, StoreProvider: &mockstorage.MockStoreProvider{
			Store: s}, KeyManager: &mockkms.KeyManager{}, VDR: &vdr.MockVDRegistry{
			CreateFunc: func(s string, doc *did.Doc, option ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return &did.DocResolution{DIDDocument: &did.Doc{ID: "did:ex:123"}}, nil
			}}})
		require.Error(t, err)
	})

	t.Run("test failed to create store", func(t *testing.T) {
		_, err := operation.New(&operation.Config{StoreProvider: &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf("failed to open store")}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
	})

	t.Run("test failed to export public key", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		_, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{
				Store: s}, KeyManager: &mockkms.KeyManager{CrAndExportPubKeyErr: fmt.Errorf("failed to export")}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to export")
	})

	t.Run("test failed to get config", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.ErrGet = fmt.Errorf("failed to get config")
		_, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get config")
	})
}

func TestOperation_CreateAuthorization(t *testing.T) {
	t.Run("TODO - creates an authorization", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.CreateAuthorization(result, nil)
		require.Equal(t, http.StatusCreated, result.Code)
		require.Contains(t, result.Body.String(), "fakeZCAP")
	})
}

func TestOperation_Compare(t *testing.T) {
	t.Run("test bad request", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.Compare(result, newReq(t,
			http.MethodPost,
			"/compare",
			nil,
		))

		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "bad request")
	})

	t.Run("test failed to get doc meta from vault server", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost", VaultBaseURL: serv.URL,
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		cr := &openapi.Comparison{}
		eq := &openapi.EqOp{}
		query := make([]openapi.Query, 0)
		docID := "docID1"
		vaultID := "vaultID1"
		query = append(query, &openapi.DocQuery{DocID: &docID, VaultID: &vaultID})
		eq.SetArgs(query)
		cr.SetOp(eq)
		op.Compare(result, newReq(t,
			http.MethodPost,
			"/compare",
			cr,
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to get doc meta")
	})

	t.Run("test error from compare csh", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			p := vault.DocumentMetadata{ID: "id", URI: "/test/test/test/test"}
			b, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		cshServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: cshServ.URL, VaultBaseURL: serv.URL,
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		cr := &openapi.Comparison{}
		eq := &openapi.EqOp{}
		query := make([]openapi.Query, 0)
		docID := "docID2"
		vaultID := "vaultID2"
		query = append(query, &openapi.DocQuery{DocID: &docID, VaultID: &vaultID,
			AuthTokens: &openapi.DocQueryAO1AuthTokens{Edv: "edvToken", Kms: "kmsToken"}})
		eq.SetArgs(query)
		cr.SetOp(eq)
		op.Compare(result, newReq(t,
			http.MethodPost,
			"/compare",
			cr,
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to execute comparison")
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			p := vault.DocumentMetadata{ID: "id", URI: "/test/test/test/test"}
			b, err := json.Marshal(p)
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		cshServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			p := models.Comparison{Result: true}
			b, err := p.MarshalBinary()
			require.NoError(t, err)

			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: cshServ.URL, VaultBaseURL: serv.URL,
			StoreProvider: &mockstorage.MockStoreProvider{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		cr := &openapi.Comparison{}
		eq := &openapi.EqOp{}
		query := make([]openapi.Query, 0)
		docID := "docID3"
		vaultID := "vaultID3"
		query = append(query, &openapi.DocQuery{DocID: &docID, VaultID: &vaultID,
			AuthTokens: &openapi.DocQueryAO1AuthTokens{Edv: "edvToken", Kms: "kmsToken"}})
		eq.SetArgs(query)
		cr.SetOp(eq)
		op.Compare(result, newReq(t,
			http.MethodPost,
			"/compare",
			cr,
		))

		require.Equal(t, http.StatusOK, result.Code)
		require.Contains(t, result.Body.String(), "true")
	})
}

func TestOperation_Extract(t *testing.T) {
	t.Run("TODO - performs an extraction", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{
				Store: s}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.Extract(result, nil)
		require.Equal(t, http.StatusOK, result.Code)
	})
}

func TestOperation_GetConfig(t *testing.T) {
	t.Run("get config success", func(t *testing.T) {
		s := make(map[string][]byte)
		s["config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{Store: s}}})
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.GetConfig(result, nil)
		require.Equal(t, http.StatusOK, result.Code)
		require.Contains(t, result.Body.String(), "did")
	})

	t.Run("get config not found", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{
				Store: s}})
		delete(s.Store, "config")
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.GetConfig(result, nil)
		require.Equal(t, http.StatusNotFound, result.Code)
	})

	t.Run("get config error", func(t *testing.T) {
		s := &mockstorage.MockStore{Store: make(map[string][]byte)}
		s.Store["config"] = []byte(`{}`)
		op, err := operation.New(&operation.Config{CSHBaseURL: "https://localhost",
			StoreProvider: &mockstorage.MockStoreProvider{
				Store: s}})
		s.ErrGet = fmt.Errorf("failed to get config")
		require.NoError(t, err)
		require.NotNil(t, op)
		result := httptest.NewRecorder()
		op.GetConfig(result, nil)
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to get config")
	})
}

func newReq(t *testing.T, method, path string, payload interface{}) *http.Request { //nolint: unparam
	t.Helper()

	var body io.Reader

	if payload != nil {
		raw, err := json.Marshal(payload)
		require.NoError(t, err)

		body = bytes.NewReader(raw)
	}

	return httptest.NewRequest(method, path, body)
}

func newZCAP(t *testing.T, server, rp *context.Provider) *zcapld.Capability {
	t.Helper()

	_, pubKeyBytes, err := rp.KMS().CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	invoker := didKeyURL(pubKeyBytes)

	signer, err := signature.NewCryptoSigner(server.Crypto(), server.KMS(), kms.ED25519Type)
	require.NoError(t, err)

	verificationMethod := didKeyURL(signer.PublicKeyBytes())

	zcap, err := zcapld.NewCapability(
		&zcapld.Signer{
			SignatureSuite:     ed25519signature2018.New(suite.WithSigner(signer)),
			SuiteType:          ed25519signature2018.SignatureType,
			VerificationMethod: verificationMethod,
		},
		zcapld.WithID(uuid.New().String()),
		zcapld.WithInvoker(invoker),
		zcapld.WithController(invoker),
		zcapld.WithInvocationTarget(
			fmt.Sprintf("https://kms.example.com/kms/keystores/%s", uuid.New().String()),
			"urn:confidentialstoragehub:profile",
		),
	)
	require.NoError(t, err)

	return zcap
}

func newAgent(t *testing.T) *context.Provider {
	t.Helper()

	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
	)
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	return ctx
}

func didKeyURL(pubKeyBytes []byte) string {
	_, didKeyURL := fingerprint.CreateDIDKey(pubKeyBytes)

	return didKeyURL
}

func compress(t *testing.T, msg []byte) string {
	t.Helper()

	compressed := bytes.NewBuffer(nil)
	compressor := gzip.NewWriter(compressed)

	_, err := compressor.Write(msg)
	require.NoError(t, err)

	err = compressor.Close()
	require.NoError(t, err)

	return base64.URLEncoding.EncodeToString(compressed.Bytes())
}

func marshal(t *testing.T, v interface{}) []byte {
	t.Helper()

	bits, err := json.Marshal(v)
	require.NoError(t, err)

	return bits
}
