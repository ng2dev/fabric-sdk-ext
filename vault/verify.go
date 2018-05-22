/*
Copyright Hyperledger and its contributors.

SPDX-License-Identifier: Apache-2.0
*/

package vault

import (
	"encoding/base64"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/pkg/errors"
	"github.com/unchainio/fabric-sdk-ext/vault/internal"
)

// Verify verifies signature against key k and digest
// The opts argument should be appropriate for the algorithm used.
func (csp *CryptoSuite) Verify(k core.Key, signature, digest []byte, opts core.SignerOpts) (valid bool, err error) {
	keyID, err := csp.loadKeyID(k.SKI())

	if err != nil {
		return false, err
	}

	secret, err := csp.client.Logical().Write(
		"fabric/transit/verify/"+keyID,

		map[string]interface{}{
			"input":     base64.StdEncoding.EncodeToString(digest),
			"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(signature),
			"prehashed": true,
		},
	)

	if err != nil {
		return false, errors.Wrapf(err, "failed to verify the signature")
	}

	return internal.NewSecretWrapper(secret).ParseVerification(), nil
}
