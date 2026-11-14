// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package slices backports the subset of Go's slices package used by Tailscale.
package slices

import (
	"sort"

	"github.com/metacubex/tailscale/util/go120/cmp"
	"github.com/metacubex/tailscale/util/go120/iter"
	"golang.org/x/exp/constraints"
	xslices "golang.org/x/exp/slices"
)

func All[S ~[]E, E any](s S) iter.Seq2[int, E] {
	return func(yield func(int, E) bool) {
		for i, v := range s {
			if !yield(i, v) {
				return
			}
		}
	}
}

func Values[S ~[]E, E any](s S) iter.Seq[E] {
	return func(yield func(E) bool) {
		for _, v := range s {
			if !yield(v) {
				return
			}
		}
	}
}

func Backward[S ~[]E, E any](s S) iter.Seq2[int, E] {
	return func(yield func(int, E) bool) {
		for i := len(s) - 1; i >= 0; i-- {
			if !yield(i, s[i]) {
				return
			}
		}
	}
}

func Collect[E any](seq iter.Seq[E]) []E {
	var s []E
	seq(func(v E) bool {
		s = append(s, v)
		return true
	})
	return s
}

func Sorted[E constraints.Ordered](seq iter.Seq[E]) []E {
	s := Collect(seq)
	Sort(s)
	return s
}

func SortedFunc[E any](seq iter.Seq[E], cmp func(E, E) int) []E {
	s := Collect(seq)
	SortFunc(s, cmp)
	return s
}

func AppendSeq[S ~[]E, E any](s S, seq iter.Seq[E]) S {
	seq(func(v E) bool {
		s = append(s, v)
		return true
	})
	return s
}

func Equal[S ~[]E, E comparable](s1, s2 S) bool { return xslices.Equal(s1, s2) }

func EqualFunc[S1 ~[]E1, S2 ~[]E2, E1, E2 any](s1 S1, s2 S2, eq func(E1, E2) bool) bool {
	return xslices.EqualFunc(s1, s2, eq)
}

func Clone[S ~[]E, E any](s S) S { return xslices.Clone(s) }

func Compact[S ~[]E, E comparable](s S) S { return xslices.Compact(s) }

func CompactFunc[S ~[]E, E any](s S, eq func(E, E) bool) S { return xslices.CompactFunc(s, eq) }

func Contains[S ~[]E, E comparable](s S, v E) bool { return xslices.Contains(s, v) }

func ContainsFunc[S ~[]E, E any](s S, f func(E) bool) bool { return xslices.ContainsFunc(s, f) }

func Delete[S ~[]E, E any](s S, i, j int) S { return xslices.Delete(s, i, j) }

func DeleteFunc[S ~[]E, E any](s S, del func(E) bool) S { return xslices.DeleteFunc(s, del) }

func Grow[S ~[]E, E any](s S, n int) S { return xslices.Grow(s, n) }

func Index[S ~[]E, E comparable](s S, v E) int { return xslices.Index(s, v) }

func IndexFunc[S ~[]E, E any](s S, f func(E) bool) int { return xslices.IndexFunc(s, f) }

func Insert[S ~[]E, E any](s S, i int, v ...E) S { return xslices.Insert(s, i, v...) }

func Sort[S ~[]E, E constraints.Ordered](s S) { xslices.Sort(s) }

func SortFunc[S ~[]E, E any](s S, f func(a, b E) int) { xslices.SortFunc(s, f) }

func SortStableFunc[S ~[]E, E any](s S, f func(a, b E) int) {
	sort.SliceStable(s, func(i, j int) bool { return f(s[i], s[j]) < 0 })
}

func MinFunc[S ~[]E, E any](s S, f func(a, b E) int) E { return xslices.MinFunc(s, f) }

func MaxFunc[S ~[]E, E any](s S, f func(a, b E) int) E { return xslices.MaxFunc(s, f) }

func BinarySearch[S ~[]E, E constraints.Ordered](s S, target E) (int, bool) {
	return xslices.BinarySearch(s, target)
}

func BinarySearchFunc[S ~[]E, E, T any](s S, target T, f func(E, T) int) (int, bool) {
	return xslices.BinarySearchFunc(s, target, f)
}

func Concat[S ~[]E, E any](slices ...S) S {
	var size int
	for _, s := range slices {
		size += len(s)
	}
	out := make(S, 0, size)
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}

func CompareFunc[S1 ~[]E1, S2 ~[]E2, E1, E2 any](s1 S1, s2 S2, f func(E1, E2) int) int {
	n := len(s1)
	if len(s2) < n {
		n = len(s2)
	}
	for i := 0; i < n; i++ {
		if c := f(s1[i], s2[i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(s1), len(s2))
}

func Compare[S1 ~[]E, S2 ~[]E, E constraints.Ordered](s1 S1, s2 S2) int {
	return CompareFunc(s1, s2, cmp.Compare[E])
}

func IsSorted[S ~[]E, E constraints.Ordered](s S) bool { return xslices.IsSorted(s) }

func Max[S ~[]E, E constraints.Ordered](s S) E { return xslices.Max(s) }

func Min[S ~[]E, E constraints.Ordered](s S) E { return xslices.Min(s) }
