package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"os"

	"log"

	"github.com/salrashid123/grpc-cert-provider/example/echo"

	//tpmfile "github.com/salrashid123/grpc-cert-provider/tpm"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/tls/certprovider/pemfile"
	"google.golang.org/grpc/security/advancedtls"

	genericsigner "github.com/salrashid123/mtls-tokensource/signer"
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

	rs, err := genericsigner.NewGenericSignerTLS(&genericsigner.GenericSignerTLS{
		Signer:              rk.(crypto.Signer),
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
