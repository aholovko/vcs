/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package spi

import (
	"net/url"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
)

type Payload []byte

type Event struct {
	// SpecVersion is spec version(required).
	SpecVersion string `json:"specversion"`

	// ID identifies the event(required).
	ID string `json:"id"`

	// Source is URI for producer(required).
	Source string `json:"source"`

	// Type defines event type(required).
	Type string `json:"type"`

	// DataContentType is data content type(required).
	DataContentType string `json:"datacontenttype"`

	// Time defines time of occurrence(required).
	Time *util.TimeWrapper `json:"time"`

	// Data defines message(required).
	Data Payload `json:"data"`
}

// Copy an event.
func (m *Event) Copy() *Event {
	return &Event{
		SpecVersion:     m.SpecVersion,
		DataContentType: m.DataContentType,
		ID:              m.ID,
		Source:          m.Source,
		Type:            m.Type,
		Time:            m.Time,
		Data:            m.Data,
	}
}

// NewEvent creates a new Event.
func NewEvent(uuid string, source *url.URL, eventType string, payload Payload) *Event {
	now := time.Now()

	return &Event{
		SpecVersion:     "1.0",
		DataContentType: "application/json",
		ID:              uuid,
		Source:          source.String(),
		Type:            eventType,
		Time:            util.NewTime(now),
		Data:            payload,
	}
}

// Options contains publisher/subscriber options.
type Options struct {
	PoolSize      int
	DeliveryDelay time.Duration
}

// Option specifies a publisher/subscriber option.
type Option func(option *Options)

// WithPool sets the pool size.
func WithPool(size int) Option {
	return func(option *Options) {
		option.PoolSize = size
	}
}

// WithDeliveryDelay sets the delivery delay.
// Note: Not all message brokers support this option.
func WithDeliveryDelay(delay time.Duration) Option {
	return func(option *Options) {
		option.DeliveryDelay = delay
	}
}