package signer

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"

	genericsigner "github.com/salrashid123/mtls-tokensource/signer"
	"google.golang.org/grpc/credentials/tls/certprovider"
	"google.golang.org/grpc/grpclog"
)

var (
	// For overriding from unit tests.
	newDistributor = func() distributor { return certprovider.NewDistributor() }

	logger = grpclog.Component("signer")
)

// Options configures a certificate provider plugin that watches a specified set
// of files that contain certificates and keys in PEM format.
type Options struct {
	// CertFile is the file that holds the identity certificate.
	// Optional. If this is set, KeyFile must also be set.
	CertFile string
	// KeyFile is anything that implements a crypto.Signer
	Signer crypto.Signer
}

func (o Options) canonical() []byte {
	return []byte(fmt.Sprintf("%s:%s", o.CertFile))
}

func (o Options) validate() error {

	if o.CertFile == "" || o.Signer == nil {
		return fmt.Errorf("signer: both cert and crypto.Signer must be set")
	}
	return nil
}

// NewProvider returns a new certificate provider plugin that is configured to use TPM based private keys.
func NewProvider(o Options) (certprovider.Provider, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	return newProvider(o), nil
}

// newProvider is used to create a new certificate provider plugin after
// validating the options, and hence does not return an error.
func newProvider(o Options) certprovider.Provider {
	provider := &handler{opts: o}
	if o.CertFile != "" && o.Signer != nil {
		provider.identityDistributor = newDistributor()
	}
	provider.signer = o.Signer
	return provider
}

// handler is a certificate provider plugin that implements the
// certprovider.Provider interface.
type handler struct {
	identityDistributor distributor
	opts                Options
	signer              crypto.Signer
}

// distributor wraps the methods on certprovider.Distributor which are used by
// the plugin. This is very useful in tests which need to know exactly when the
// plugin updates its key material.
type distributor interface {
	KeyMaterial(ctx context.Context) (*certprovider.KeyMaterial, error)
	Set(km *certprovider.KeyMaterial, err error)
	Stop()
}

func (w *handler) KeyMaterial(ctx context.Context) (*certprovider.KeyMaterial, error) {
	km := &certprovider.KeyMaterial{}

	rs, err := genericsigner.NewGenericSignerTLS(&genericsigner.GenericSignerTLS{
		Signer:              w.signer,
		MtlsCertificateFile: w.opts.CertFile,
	})
	if err != nil {
		logger.Warningf("error getting generic tls signer %v\n", err)
		return km, err
	}

	tcrt, err := rs.TLSCertificate()
	if err != nil {
		logger.Warningf("Error reading TPM tls certificate %v\n", err)
		return km, err
	}

	km.Certs = []tls.Certificate{tcrt}

	return km, nil
}

// Close cleans up resources allocated by the watcher.
func (w *handler) Close() {}
