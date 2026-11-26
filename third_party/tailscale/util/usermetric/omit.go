// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_enable_usermetrics

package usermetric

type Registry struct {
	m Metrics
}

func (*Registry) NewGauge(name, help string) *Gauge { return nil }

type MultiLabelMap[T comparable] struct{}

type Gauge struct{}

func (*Gauge) Set(float64) {}

func NewMultiLabelMapWithRegistry[T comparable](m *Registry, name string, promType, helpText string) *MultiLabelMap[T] {
	return nil
}

func (*MultiLabelMap[T]) Add(T, int64) {}
func (*MultiLabelMap[T]) Set(T, any)   {}

func (r *Registry) Handler(any, any) {} // no-op HTTP handler
