// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cosigner_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/cosigner"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestSimpleCosigner(t *testing.T) {
	// Generate the key pair for our cosigner
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err, "failed to generate key pair")

	cos := &cosigner.Cosigner{
		Alg:    alg,
		Signer: signer,
	}

	pkt, err := mocks.GenerateMockPKToken(t, signer, alg)
	require.NoError(t, err)

	cosignerClaims := pktoken.CosignerClaims{
		Issuer:      "example.com",
		KeyID:       "none",
		Algorithm:   cos.Alg.String(),
		AuthID:      "none",
		AuthTime:    time.Now().Unix(),
		IssuedAt:    time.Now().Unix(),
		Expiration:  time.Now().Add(time.Hour).Unix(),
		RedirectURI: "none",
		Nonce:       "test-nonce",
		Typ:         "COS",
	}

	cosToken, err := cos.Cosign(pkt, cosignerClaims)
	require.NoError(t, err, "failed cosign PK Token")
	require.NotNil(t, cosToken, "cosign signature is nil")
}
