module github.com/salrashid123/grpc-cert-provider/tpm

go 1.22.4

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20240805214234-f870d6f1ff68
	github.com/google/go-tpm v0.9.1
	github.com/google/go-tpm-tools v0.4.4
	github.com/salrashid123/mtls-tokensource/signer v0.0.0-20241022124513-e840c0a671ad
	github.com/salrashid123/signer/tpm v0.0.0-20240617111903-89bbd6f3aaad
	google.golang.org/grpc v1.67.1
)

require (
	golang.org/x/crypto v0.28.0 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/oauth2 v0.23.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/text v0.19.0 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
)
