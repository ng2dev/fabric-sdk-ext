/*
Copyright Hyperledger and its contributors.

SPDX-License-Identifier: Apache-2.0
*/

package vault

import (
	"crypto/sha256"
	"crypto/sha512"

	vault "github.com/hashicorp/vault/api"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/unchainio/fabric-sdk-ext/cryptosuite/vault/internal"
)

// Constants describing encryption algorithms
const (
	ECDSAP256 = "ecdsa-p256"
	RSA2048   = "rsa-2048"
	RSA4096   = "rsa-4096"
)

var logger = logging.NewLogger("fabsdk/core")

// CryptoSuite is a vault implementation of the core.CryptoSuite interface
type CryptoSuite struct {
	hashers map[string]Hasher
	client  *vault.Client
}

// options configure a new CryptoSuite. options are set by the OptionFunc values passed to NewCryptoSuite.
type options struct {
	client  *vault.Client
	hashers map[string]Hasher
	config  core.CryptoSuiteConfig
}

// OptionFunc configures how the CryptoSuite is set up.
type OptionFunc func(*options) error

// NewCryptoSuite constructs a new CryptoSuite, configured via provided OptionFuncs
func NewCryptoSuite(optFuncs ...OptionFunc) (*CryptoSuite, error) {
	var err error
	opts := &options{}

	for _, optFunc := range optFuncs {
		err = optFunc(opts)

		if err != nil {
			return nil, err
		}
	}

	if opts.client == nil {
		opts.client, err = getVaultClient(opts.config)

		if err != nil {
			return nil, err
		}
	}

	hashers := getHashers(opts.config)

	for key, hasher := range opts.hashers {
		hashers[key] = hasher
	}

	logger.Debug("Initialized the vault CryptoSuite")

	return &CryptoSuite{
		client:  opts.client,
		hashers: hashers,
	}, nil
}

func getHashers(cfg core.CryptoSuiteConfig) map[string]Hasher {
	if cfg == nil {
		return nil
	}

	defaultHasher := parseHasher(cfg.SecurityAlgorithm())

	// Set the hashers
	hashers := make(map[string]Hasher)

	if defaultHasher != nil {
		hashers[bccsp.SHA] = defaultHasher
	}

	hashers[bccsp.SHA256] = &internal.Hasher{HashFunc: sha256.New}
	hashers[bccsp.SHA384] = &internal.Hasher{HashFunc: sha512.New384}
	hashers[bccsp.SHA3_256] = &internal.Hasher{HashFunc: sha3.New256}
	hashers[bccsp.SHA3_384] = &internal.Hasher{HashFunc: sha3.New384}

	return hashers
}

func parseHasher(algorithm string) *internal.Hasher {
	switch algorithm {
	case bccsp.SHA256:
		return &internal.Hasher{HashFunc: sha256.New}
	case bccsp.SHA384:
		return &internal.Hasher{HashFunc: sha512.New384}
	case bccsp.SHA3_256:
		return &internal.Hasher{HashFunc: sha3.New256}
	case bccsp.SHA3_384:
		return &internal.Hasher{HashFunc: sha3.New384}

	default:
		return nil
	}
}

// WithClient allows to set the vault client of the CryptoSuite
func WithClient(client *vault.Client) OptionFunc {
	return func(o *options) error {
		o.client = client
		return nil
	}
}

// WithHashers allows to provide additional hashers to the CryptoSuite
func WithHashers(hashers map[string]Hasher) OptionFunc {
	return func(o *options) error {
		o.hashers = hashers
		return nil
	}
}

// FromConfig uses a core.CryptoSuiteConfig to configure the vault client of the CryptoSuite
func FromConfig(config core.CryptoSuiteConfig) OptionFunc {
	return func(o *options) error {
		o.config = config
		return nil
	}
}

func getVaultClient(config core.CryptoSuiteConfig) (*vault.Client, error) {
	if config == nil {
		return nil, errors.New("unable to obtain vault client configuration from nil CryptoSuiteConfig")
	}

	vaultConfig := &vault.Config{
		Address: config.SecurityProviderAddress(),
	}

	client, err := vault.NewClient(vaultConfig)

	if err != nil {
		return nil, errors.Wrapf(err, "could not initialize Vault BCCSP for address: %s", vaultConfig.Address)
	}

	client.SetToken(config.SecurityProviderToken())

	return client, nil
}
