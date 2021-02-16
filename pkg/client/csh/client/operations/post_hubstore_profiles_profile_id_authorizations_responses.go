// Code generated by go-swagger; DO NOT EDIT.

// /*
// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
// */
//

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/trustbloc/edge-service/pkg/client/csh/models"
)

// PostHubstoreProfilesProfileIDAuthorizationsReader is a Reader for the PostHubstoreProfilesProfileIDAuthorizations structure.
type PostHubstoreProfilesProfileIDAuthorizationsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostHubstoreProfilesProfileIDAuthorizationsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPostHubstoreProfilesProfileIDAuthorizationsCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 500:
		result := NewPostHubstoreProfilesProfileIDAuthorizationsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPostHubstoreProfilesProfileIDAuthorizationsCreated creates a PostHubstoreProfilesProfileIDAuthorizationsCreated with default headers values
func NewPostHubstoreProfilesProfileIDAuthorizationsCreated() *PostHubstoreProfilesProfileIDAuthorizationsCreated {
	return &PostHubstoreProfilesProfileIDAuthorizationsCreated{}
}

/* PostHubstoreProfilesProfileIDAuthorizationsCreated describes a response with status code 201, with default header values.

The new authorization.
*/
type PostHubstoreProfilesProfileIDAuthorizationsCreated struct {

	/* Location of the authorization.
	 */
	Location string

	Payload *models.Authorization
}

func (o *PostHubstoreProfilesProfileIDAuthorizationsCreated) Error() string {
	return fmt.Sprintf("[POST /hubstore/profiles/{profileID}/authorizations][%d] postHubstoreProfilesProfileIdAuthorizationsCreated  %+v", 201, o.Payload)
}
func (o *PostHubstoreProfilesProfileIDAuthorizationsCreated) GetPayload() *models.Authorization {
	return o.Payload
}

func (o *PostHubstoreProfilesProfileIDAuthorizationsCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header Location
	hdrLocation := response.GetHeader("Location")

	if hdrLocation != "" {
		o.Location = hdrLocation
	}

	o.Payload = new(models.Authorization)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostHubstoreProfilesProfileIDAuthorizationsInternalServerError creates a PostHubstoreProfilesProfileIDAuthorizationsInternalServerError with default headers values
func NewPostHubstoreProfilesProfileIDAuthorizationsInternalServerError() *PostHubstoreProfilesProfileIDAuthorizationsInternalServerError {
	return &PostHubstoreProfilesProfileIDAuthorizationsInternalServerError{}
}

/* PostHubstoreProfilesProfileIDAuthorizationsInternalServerError describes a response with status code 500, with default header values.

Generic Error
*/
type PostHubstoreProfilesProfileIDAuthorizationsInternalServerError struct {
	Payload *models.Error
}

func (o *PostHubstoreProfilesProfileIDAuthorizationsInternalServerError) Error() string {
	return fmt.Sprintf("[POST /hubstore/profiles/{profileID}/authorizations][%d] postHubstoreProfilesProfileIdAuthorizationsInternalServerError  %+v", 500, o.Payload)
}
func (o *PostHubstoreProfilesProfileIDAuthorizationsInternalServerError) GetPayload() *models.Error {
	return o.Payload
}

func (o *PostHubstoreProfilesProfileIDAuthorizationsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
