// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/cilium/tetragon/pkg/testutils"
)

func TestUprobeValidationMultiplePreloadArguments(t *testing.T) {

	// Using multiple preload arguments

	uprobe := testutils.RepoRootPath("contrib/tester-progs/usdt-override")
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + uprobe + `"
    symbols:
    - "test_3"
    data:
    - index: 0
      type: "string"
      source: "pt_regs"
      resolve: "rdi"
    - index: 1
      type: "string"
      source: "pt_regs"
      resolve: "rsi"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}

func testUprobeValidationSymbolsAddrsOffsets(t *testing.T, withSymbol, withAdrr, withOff bool) {
	uprobe := testutils.RepoRootPath("contrib/tester-progs/usdt-override")
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + uprobe + `"`
	if withSymbol {
		crd += "    symbols: [\"test_3\"]\n"
	}
	if withAdrr {
		crd += "    addrs: [0x985256]\n"
	}
	if withOff {
		crd += "    offsets: [0x9156366]\n"
	}

	_, err := tracingpolicy.FromYAML(crd)
	require.Error(t, err)
}

func TestUprobeValidationSymbolsAddrsOffsets(t *testing.T) {
	testUprobeValidationSymbolsAddrsOffsets(t, true, true, true)
}

func TestUprobeValidationSymbolsAddrs(t *testing.T) {
	testUprobeValidationSymbolsAddrsOffsets(t, true, true, false)
}

func TestUprobeValidationSymbolsOffsets(t *testing.T) {
	testUprobeValidationSymbolsAddrsOffsets(t, true, false, true)
}

func TestUprobeValidationAddrsOffsets(t *testing.T) {
	testUprobeValidationSymbolsAddrsOffsets(t, false, true, true)
}

func TestUprobeValidationReturnWithoutArg(t *testing.T) {
	uprobe := testutils.RepoRootPath("contrib/tester-progs/usdt-override")
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + uprobe + `"
    symbols:
    - "test_3"
    return: true
`

	_, err := tracingpolicy.FromYAML(crd)
	require.Error(t, err)
}
