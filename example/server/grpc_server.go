package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"net"
	"os"

	"github.com/salrashid123/grpc-cert-provider/example/echo"

	"log"

	"github.com/google/uuid"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
)

var (
	tlsCert  = flag.String("tlsCert", "", "tls Certificate")
	tlsKey   = flag.String("tlsKey", "", "tls Key")
	grpcport = flag.String("grpcport", "", "grpcport")
	clientCA = flag.String("clientCA", "", "tls client root Certificate")
)

const (
	address string = ":50051"
)

type server struct{}

// NewServer returns a new Server.
func NewServer() *server {
	return &server{}
}

type contextKey string

func authUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	//md, _ := metadata.FromIncomingContext(ctx)

	peer, ok := peer.FromContext(ctx)
	if ok {
		log.Printf("     Using mTLS Client cert Peer IP and SerialNumber")
		tlsInfo := peer.AuthInfo.(credentials.TLSInfo)
		if len(tlsInfo.State.VerifiedChains) > 0 && len(tlsInfo.State.VerifiedChains[0]) > 0 {
			v := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
			sn := tlsInfo.State.VerifiedChains[0][0].SerialNumber
			log.Printf("     Client Peer Address [%v] - Subject[%v] - SerialNumber [%v] Validated\n", peer.Addr.String(), v, sn)
		} else {
			log.Printf("ERROR:  Could not parse Peer Certificate")
			return nil, status.Errorf(codes.PermissionDenied, "Could not parse Peer Certificate")
		}
	}

	newCtx := context.WithValue(ctx, contextKey("idtoken"), "foo")

	return handler(newCtx, req)

}

func (s *server) SayHelloUnary(ctx context.Context, in *echo.EchoRequest) (*echo.EchoReply, error) {
	log.Println("Got Unary Request: ")
	uid, _ := uuid.NewUUID()
	return &echo.EchoReply{Message: "SayHelloUnary Response " + uid.String()}, nil
}

func main() {

	flag.Parse()

	if *grpcport == "" {
		flag.Usage()
		log.Panicf("missing -grpcport flag (:50051)")
	}

	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	sopts := []grpc.ServerOption{}

	serverCert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	if err != nil {
		log.Fatalf("Failed to generate credentials %v", err)
	}

	clientrootCAs := x509.NewCertPool()
	pem, err := os.ReadFile(*clientCA)
	if err != nil {
		log.Fatalf("failed to load root CA certificates  error=%v", err)
	}
	if !clientrootCAs.AppendCertsFromPEM(pem) {
		log.Fatalf("no root CA certs parsed from file ")
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientrootCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	sopts = append(sopts, grpc.UnaryInterceptor(authUnaryInterceptor), grpc.Creds(credentials.NewTLS(config)))

	s := grpc.NewServer(sopts...)
	srv := NewServer()
	echo.RegisterEchoServerServer(s, srv)

	log.Println("Starting Server...")
	s.Serve(lis)

}
