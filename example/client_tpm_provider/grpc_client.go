package main

import (
	"flag"
	"io"
	"net"
	"slices"

	"log"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/salrashid123/grpc-cert-provider/example/echo"

	//tpmfile "github.com/salrashid123/grpc-cert-provider/tpm"
	tpmfile "github.com/salrashid123/grpc-cert-provider/tpm"
	tpmsigner "github.com/salrashid123/signer/tpm"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/tls/certprovider/pemfile"
	"google.golang.org/grpc/security/advancedtls"
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
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

	// open the tpm
	rwc, err := openTPM(*tpmPath)
	if err != nil {
		log.Fatalf("tpm.openTPM failed: %v", err)
		return
	}
	// always close
	defer rwc.Close()

	rwr := transport.FromReadWriter(rwc)

	// create a password session (if you have a password set for the object)
	sess, err := tpmsigner.NewPasswordSession(rwr, []byte(*keyPassword))
	if err != nil {
		log.Fatalf("tpm.NewPasswordSession failed: %v", err)
	}

	// set the options
	identityOptions := tpmfile.Options{
		CertFile:    *tlsCert,
		KeyFile:     *tlsKey,
		TPMDevice:   rwc,
		AuthSession: sess,
	}
	identityProvider, err := tpmfile.NewProvider(identityOptions)
	if err != nil {
		log.Fatalf("tpm.NewProvider(%v) failed: %v", identityOptions, err)
	}
	// must to close TPM object handles
	defer identityProvider.Close()

	// the root key provider is a basic pem so we use the standard provider here
	rootOptions := pemfile.Options{
		RootFile: *rootCA,
	}

	rootProvider, err := pemfile.NewProvider(rootOptions)
	if err != nil {
		log.Fatalf("tpm.NewProvider(%v) failed: %v", rootOptions, err)
	}

	// ************

	options := &advancedtls.Options{
		IdentityOptions: advancedtls.IdentityCertificateOptions{
			IdentityProvider: identityProvider,
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
