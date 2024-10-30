module main

go 1.22.4

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20240805214234-f870d6f1ff68
	github.com/google/go-tpm v0.9.1
	github.com/google/go-tpm-tools v0.4.4
	github.com/google/uuid v1.6.0
	github.com/salrashid123/grpc-cert-provider/example/echo v0.0.0
	github.com/salrashid123/grpc-cert-provider/tpm v0.0.0
	github.com/salrashid123/grpc-cert-provider/signer v0.0.0	
	github.com/salrashid123/mtls-tokensource/signer v0.0.0-20241022124513-e840c0a671ad
	github.com/salrashid123/signer/tpm v0.0.0-20240617111903-89bbd6f3aaad
	golang.org/x/net v0.30.0
	google.golang.org/grpc v1.67.1
	google.golang.org/grpc/security/advancedtls v1.0.0
)

require (
	github.com/google/go-configfs-tsm v0.3.2 // indirect
	golang.org/x/crypto v0.28.0 // indirect
	golang.org/x/oauth2 v0.23.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/text v0.19.0 // indirect
	google.golang.org/genproto v0.0.0-20211118181313-81c1377c94b1 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
)

replace github.com/salrashid123/grpc-cert-provider/example/echo => ./echo

replace github.com/salrashid123/grpc-cert-provider/tpm => ../tpm

replace github.com/salrashid123/grpc-cert-provider/signer => ../signer