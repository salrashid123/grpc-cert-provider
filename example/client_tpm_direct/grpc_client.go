package main

import (
	"crypto/tls"
	"flag"
	"io"
	"net"
	"os"
	"slices"

	"log"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/salrashid123/grpc-cert-provider/example/echo"

	//tpmfile "github.com/salrashid123/grpc-cert-provider/tpm"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/tls/certprovider/pemfile"
	"google.golang.org/grpc/security/advancedtls"

	genericsigner "github.com/salrashid123/mtls-tokensource/signer"
	tpmsigner "github.com/salrashid123/signer/tpm"
)

const ()

var ()

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {

	address := flag.String("host", "localhost:50051", "host:port of gRPC server")
	rootCA := flag.String("rootCA", "", "tls root Certificate")
	tlsCert := flag.String("tlsCert", "", "tls Certificate")
	tlsKey := flag.String("tlsKey", "", "tls Key")
	serverName := flag.String("servername", "grpc.domain.com", "CACert for server")
	tpmPath := flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	keyPassword := flag.String("keyPassword", "", "key passphrase")

	flag.Parse()

	rootOptions := pemfile.Options{
		RootFile: *rootCA,
	}

	rootProvider, err := pemfile.NewProvider(rootOptions)
	if err != nil {
		log.Fatalf("pemfile.NewProvider(%v) failed: %v", rootOptions, err)
	}

	// **************
	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()
	rwr := transport.FromReadWriter(rwc)
	// pub, err := tpm2.ReadPublic{
	// 	ObjectHandle: tpm2.TPMHandle(*persistentHandle),
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("error executing tpm2.ReadPublic %v", err)
	// }

	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}

	// load the tpm-tss generated rsa key from disk

	c, err := os.ReadFile(*tlsKey)
	if err != nil {
		log.Fatalf("error reading private keyfile: %v", err)
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		log.Fatalf("failed decoding key: %v", err)
	}
	regenRSAKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primary.ObjectHandle,
			Name:   tpm2.TPM2BName(primary.Name),
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load rsa key: %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: regenRSAKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	flush := tpm2.FlushContext{
		FlushHandle: primary.ObjectHandle,
	}
	_, err = flush.Execute(rwr)
	if err != nil {
		log.Fatalf("can't close primary  %v", err)
	}

	// create a pass session (if you have a password set for the object)
	sess, err := tpmsigner.NewPasswordSession(rwr, []byte(*keyPassword))
	if err != nil {
		log.Fatalf("tpm.NewPasswordSession failed: %v", err)
	}

	tsigner, err := tpmsigner.NewTPMCrypto(&tpmsigner.TPM{
		TpmDevice: rwc,
		NamedHandle: &tpm2.NamedHandle{
			Handle: regenRSAKey.ObjectHandle,
			Name:   regenRSAKey.Name,
		},
		PublicCertFile: *tlsCert,
		AuthSession:    sess,
	})
	if err != nil {
		log.Fatal(err)
	}

	rs, err := genericsigner.NewGenericSignerTLS(&genericsigner.GenericSignerTLS{
		Signer:              tsigner,
		MtlsCertificateFile: *tlsCert,
	})
	if err != nil {
		log.Fatal(err)
	}

	tcrt, err := rs.TLSCertificate()
	if err != nil {
		log.Fatal(err)
	}
	// ************

	options := &advancedtls.Options{
		IdentityOptions: advancedtls.IdentityCertificateOptions{
			Certificates: []tls.Certificate{tcrt},
		},
		AdditionalPeerVerification: func(*advancedtls.HandshakeVerificationInfo) (*advancedtls.PostHandshakeVerificationResults, error) {
			return &advancedtls.PostHandshakeVerificationResults{}, nil
		},
		RootOptions: advancedtls.RootCertificateOptions{
			RootProvider: rootProvider,
		},
		VerificationType: advancedtls.CertAndHostVerification,
	}
	ce, err := advancedtls.NewClientCreds(options)
	if err != nil {
		log.Fatalf("advancedtls.NewClientCreds(%v) failed: %v", options, err)
	}

	conn, err := grpc.NewClient(*address, grpc.WithTransportCredentials(ce), grpc.WithAuthority(*serverName))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	ctx := context.Background()
	cr := echo.NewEchoServerClient(conn)

	r, err := cr.SayHelloUnary(ctx, &echo.EchoRequest{Name: "Unary Request"})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}

	log.Printf("Unary Response:  [%s]", r.Message)

}
