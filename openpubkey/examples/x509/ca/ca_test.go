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

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/require"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
)

func TestCACertCreation(t *testing.T) {
	providerOpts := providers.DefaultMockProviderOpts()
	op, _, _, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	certAuth, err := New(op)
	require.NoError(t, err)

	err = certAuth.KeyGen(string(jwa.ES256))
	require.NoError(t, err)

	userAlg := jwa.ES256
	userSigningKey, err := util.GenKeyPair(userAlg)
	require.NoError(t, err)

	client, err := client.New(op, client.WithSigner(userSigningKey, userAlg))
	require.NoError(t, err)

	pkt, err := client.Auth(context.Background())
	require.NoError(t, err)

	pktJson, err := json.Marshal(pkt)
	require.NoError(t, err)

	pemSubCert, err := certAuth.PktToSignedX509(pktJson)
	require.NoError(t, err)
	decodeBlock, _ := pem.Decode(pemSubCert)

	cc, err := x509.ParseCertificate(decodeBlock.Bytes)
	require.NoError(t, err)

	certPubkey := cc.PublicKey.(*ecdsa.PublicKey)

	_, err = jws.Verify(pkt.CicToken, jws.WithKey(jwa.ES256, certPubkey))
	require.NoError(t, err)

	err = certAuth.VerifyPktCert(pemSubCert)
	require.NoError(t, err)

}
