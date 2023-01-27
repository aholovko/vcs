/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httputil"

	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/event/spi"
)

func (s *Service) ExchangeAuthorizationCode(ctx context.Context, opState string) (TxID, error) {
	tx, err := s.store.FindByOpState(ctx, opState)
	if err != nil {
		return "", fmt.Errorf("get transaction by opstate: %w", err)
	}

	newState := TransactionStateIssuerOIDCAuthorizationDone
	if err = s.validateStateTransition(tx.State, newState); err != nil {
		s.sendFailedEvent(tx, err)
		return "", err
	}
	tx.State = newState

	c := s.httpClient.(*http.Client)
	c.Transport = &DumpTransport{r: c.Transport}

	resp, err := s.oAuth2Client.Exchange(ctx, oauth2.Config{
		ClientID:     tx.ClientID,
		ClientSecret: tx.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   tx.AuthorizationEndpoint,
			TokenURL:  tx.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
		RedirectURL: tx.RedirectURI,
		Scopes:      tx.Scope,
	}, tx.IssuerAuthCode, c) // TODO: Fix this!
	if err != nil {
		s.sendFailedEvent(tx, err)
		return "", err
	}

	tx.IssuerToken = resp.AccessToken

	if err = s.store.Update(ctx, tx); err != nil {
		s.sendFailedEvent(tx, err)
		return "", err
	}

	if err = s.sendEvent(tx, spi.IssuerOIDCInteractionAuthorizationCodeExchanged); err != nil {
		return "", err
	}

	return tx.ID, nil
}

// DumpTransport is http.RoundTripper that dumps request/response.
type DumpTransport struct {
	r http.RoundTripper
}

// RoundTrip implements the RoundTripper interface.
func (d *DumpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to dump request: %w", err)
	}

	fmt.Printf("REQUEST:%s\n", base64.StdEncoding.EncodeToString(reqDump))

	resp, err := d.r.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, fmt.Errorf("failed to dump response: %w", err)
	}

	fmt.Printf("RESPONSE:%s\n", base64.StdEncoding.EncodeToString(respDump))

	return resp, err
}
