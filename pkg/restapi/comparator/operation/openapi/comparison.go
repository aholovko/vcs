// Code generated by go-swagger; DO NOT EDIT.

package openapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Comparison comparison
//
// swagger:model Comparison
type Comparison struct {
	opField Operator
}

// Op gets the op of this base type
func (m *Comparison) Op() Operator {
	return m.opField
}

// SetOp sets the op of this base type
func (m *Comparison) SetOp(val Operator) {
	m.opField = val
}

// UnmarshalJSON unmarshals this object with a polymorphic type from a JSON structure
func (m *Comparison) UnmarshalJSON(raw []byte) error {
	var data struct {
		Op json.RawMessage `json:"op,omitempty"`
	}
	buf := bytes.NewBuffer(raw)
	dec := json.NewDecoder(buf)
	dec.UseNumber()

	if err := dec.Decode(&data); err != nil {
		return err
	}

	var propOp Operator
	if string(data.Op) != "null" {
		op, err := UnmarshalOperator(bytes.NewBuffer(data.Op), runtime.JSONConsumer())
		if err != nil && err != io.EOF {
			return err
		}
		propOp = op
	}

	var result Comparison

	// op
	result.opField = propOp

	*m = result

	return nil
}

// MarshalJSON marshals this object with a polymorphic type to a JSON structure
func (m Comparison) MarshalJSON() ([]byte, error) {
	var b1, b2, b3 []byte
	var err error
	b1, err = json.Marshal(struct {
	}{})
	if err != nil {
		return nil, err
	}
	b2, err = json.Marshal(struct {
		Op Operator `json:"op,omitempty"`
	}{

		Op: m.opField,
	})
	if err != nil {
		return nil, err
	}

	return swag.ConcatJSON(b1, b2, b3), nil
}

// Validate validates this comparison
func (m *Comparison) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateOp(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Comparison) validateOp(formats strfmt.Registry) error {
	if swag.IsZero(m.Op()) { // not required
		return nil
	}

	if err := m.Op().Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("op")
		}
		return err
	}

	return nil
}

// ContextValidate validate this comparison based on the context it is used
func (m *Comparison) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateOp(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Comparison) contextValidateOp(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Op().ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("op")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Comparison) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Comparison) UnmarshalBinary(b []byte) error {
	var res Comparison
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
