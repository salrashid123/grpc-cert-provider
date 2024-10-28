package tpm

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	genericsigner "github.com/salrashid123/mtls-tokensource/signer"
	tpmsigner "github.com/salrashid123/signer/tpm"
	"google.golang.org/grpc/credentials/tls/certprovider"
	"google.golang.org/grpc/grpclog"
)

var (
	// For overriding from unit tests.
	newDistributor = func() distributor { return certprovider.NewDistributor() }

	logger = grpclog.Component("tpm")
)

// Options configures a certificate provider plugin that watches a specified set
// of files that contain certificates and keys in PEM format.
type Options struct {
	// CertFile is the file that holds the identity certificate.
	// Optional. If this is set, KeyFile must also be set.
	CertFile string
	// KeyFile is the file that holds identity TPM private key in PEM format.
	KeyFile string

	// TPMDevice is the ReadWriteCloser to the tpm device or simulator
	TPMDevice io.ReadWriteCloser

	// password for the object's parent
	ParentPassword []byte

	// password for the object
	AuthSession tpmsigner.Session
}

func (o Options) canonical() []byte {
	return []byte(fmt.Sprintf("%s:%s", o.CertFile, o.KeyFile))
}

func (o Options) validate() error {
	if o.TPMDevice == nil {
		return fmt.Errorf("tpm: TPM Path must be set")
	}
	if o.CertFile == "" || o.KeyFile == "" {
		return fmt.Errorf("tpm: both cert and file must be set")
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
	if o.CertFile != "" && o.KeyFile != "" {
		provider.identityDistributor = newDistributor()
	}
	// the authsession, password and device should not get encoded to json so we're setting it here
	provider.authSession = o.AuthSession
	provider.parentPassword = o.ParentPassword
	provider.rwc = o.TPMDevice
	return provider
}

// handler is a certificate provider plugin that implements the
// certprovider.Provider interface.
type handler struct {
	identityDistributor distributor
	opts                Options
	rwc                 io.ReadWriteCloser
	rkey                tpm2.TPMHandle
	parentPassword      []byte
	authSession         tpmsigner.Session
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

	rwr := transport.FromReadWriter(w.rwc)

	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		return km, err
	}

	// load the tpm-tss generated rsa key from disk

	c, err := os.ReadFile(w.opts.KeyFile)
	if err != nil {
		return km, err
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		return km, err
	}
	regenRSAKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primary.ObjectHandle,
			Name:   tpm2.TPM2BName(primary.Name),
			Auth:   tpm2.PasswordAuth(w.parentPassword),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)
	if err != nil {
		return km, err
	}

	w.rkey = regenRSAKey.ObjectHandle

	flush := tpm2.FlushContext{
		FlushHandle: primary.ObjectHandle,
	}
	_, err = flush.Execute(rwr)
	if err != nil {
		return km, err
	}

	signer, err := tpmsigner.NewTPMCrypto(&tpmsigner.TPM{
		TpmDevice: w.rwc,
		NamedHandle: &tpm2.NamedHandle{
			Handle: regenRSAKey.ObjectHandle,
			Name:   regenRSAKey.Name,
		},
		AuthSession:    w.authSession,
		PublicCertFile: w.opts.CertFile,
	})
	if err != nil {
		logger.Warningf("error creating signer %v\n", err)
		return km, err
	}

	rs, err := genericsigner.NewGenericSignerTLS(&genericsigner.GenericSignerTLS{
		Signer:              signer,
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
func (w *handler) Close() {

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: w.rkey,
	}
	rwr := transport.FromReadWriter(w.rwc)
	_, _ = flushContextCmd.Execute(rwr)

	// if err := w.rwc.Close(); err != nil {
	// 	logger.Warningf("can't close TPM %q: %v", w.opts.TPMDevice, err)
	// }
}
