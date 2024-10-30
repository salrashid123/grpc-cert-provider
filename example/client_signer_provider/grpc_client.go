package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"os"

	"log"

	"github.com/salrashid123/grpc-cert-provider/example/echo"

	signerfile "github.com/salrashid123/grpc-cert-provider/signer"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/tls/certprovider/pemfile"
	"google.golang.org/grpc/security/advancedtls"
)

const ()

var ()

func main() {

	address := flag.String("host", "localhost:50051", "host:port of gRPC server")
	rootCA := flag.String("rootCA", "", "tls root Certificate")
	tlsCert := flag.String("tlsCert", "", "tls Certificate")
	tlsKey := flag.String("tlsKey", "", "tls Key")
	serverName := flag.String("servername", "grpc.domain.com", "CACert for server")

	flag.Parse()

	rootOptions := pemfile.Options{
		RootFile: *rootCA,
	}

	rootProvider, err := pemfile.NewProvider(rootOptions)
	if err != nil {
		log.Fatalf("pemfile.NewProvider(%v) failed: %v", rootOptions, err)
	}

	privatePEM, err := os.ReadFile(*tlsKey)
	if err != nil {
		log.Fatal(err)
	}

	rblock, _ := pem.Decode(privatePEM)
	rk, err := x509.ParsePKCS8PrivateKey(rblock.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	// set the options
	identityOptions := signerfile.Options{
		CertFile: *tlsCert,
		Signer:   rk.(crypto.Signer),
	}
	identityProvider, err := signerfile.NewProvider(identityOptions)
	if err != nil {
		log.Fatalf("tpm.NewProvider(%v) failed: %v", identityOptions, err)
	}
	// must to close TPM object handles
	defer identityProvider.Close()

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
