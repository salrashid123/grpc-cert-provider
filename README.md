## gRPC AdvancdTLS provider packages for Trusted Platform Module

Implementation for gRPC go's [grpc.security.advancedtls](https://pkg.go.dev/google.golang.org/grpc/security/advancedtls) handlers.

This specific handler supports credentials from `Trusted Platform Module (TPM)`

This utility reads PEM encoded TPM Key files as described [here](https://github.com/salrashid123/tpm2genkey?tab=readme-ov-file#pem-keyfile-format), eg:

```bash
$ cat workload1.pem
		-----BEGIN TSS2 PRIVATE KEY-----
		MIHyBgZngQUKAQOgAwEB/wIEQAAAAQRaAFgAIwALAAQAcgAAABAAGAALAAMAEAAg
		vyhagIueIzc/zlj/6AcYPdwERNqgXHeuOZCQlap+n/QAIOnU2Eeo3BXHxqzkPwTh
		tzb4o4C1/sDp8WXw5ixIjS2pBIGAAH4AIBiwkm4ibJPDDjaSZo5oze679FVuZInF
		d4twjiIeeqjIABB5LRYnQ9VhknWWI+dENozEQ7welfm37mq3GofYDXXDCSfoEE8X
		7c7X8zqONRUOwhY8nSGwql+mDMwZOc2k5rAg6ZWkrs1YkNXhuLhK1P9uvmuv6m5L
		PkkfpCY=
		-----END TSS2 PRIVATE KEY-----

$ openssl ec -provider tpm2  -provider default -in workload1.pem  --text
		read EC key
		Private-Key: (EC P-256, TPM 2.0)
		Parent: 0x40000001
		pub:
			04:bf:28:5a:80:8b:9e:23:37:3f:ce:58:ff:e8:07:
			18:3d:dc:04:44:da:a0:5c:77:ae:39:90:90:95:aa:
			7e:9f:f4:e9:d4:d8:47:a8:dc:15:c7:c6:ac:e4:3f:
			04:e1:b7:36:f8:a3:80:b5:fe:c0:e9:f1:65:f0:e6:
			2c:48:8d:2d:a9
		ASN1 OID: prime256v1
		Object Attributes:
		fixedTPM
		fixedParent
		sensitiveDataOrigin
		userWithAuth
		sign / encrypt
```

TODO: provider support `PKCS-11` and `crypto.Signer` (eg see [golang-jwt-pkcs11](https://github.com/salrashid123/golang-jwt-pkcs11) and [golang-jwt-signer](https://github.com/salrashid123/golang-jwt-signer))

>> NOTE: this repo is _not_ supported by google

Basic usage comes in two forms:


* `A)`:  `IdentityOptions.IdentityProvider`

With this you need to acquire the TPM based certificate directly before initializing an advancedtls module

the specific implementation here is loaded using

* `"github.com/salrashid123/grpc-cert-provider/tpm"`

```golang
import (
	tpmfile "github.com/salrashid123/grpc-cert-provider/tpm"
	tpmsigner "github.com/salrashid123/signer/tpm"
)
	// open tpm
	rwc, err := openTPM(*tpmPath)
	// specify the paths to the x509 cert and PEM encoded tpm key
	identityOptions := tpmfile.Options{
		CertFile:    *tlsCert,
		KeyFile:     *tlsKey,
		TPMDevice:   rwc,
	}

	// initialize the key provider
	identityProvider, err := tpmfile.NewProvider(identityOptions)
	defer identityProvider.Close()

	// apply the certificate as an IdentityOption
	options := &advancedtls.Options{
		IdentityOptions: advancedtls.IdentityCertificateOptions{
			IdentityProvider: identityProvider,
		},
	}
	ce, err := advancedtls.NewClientCreds(options)
	conn, err := grpc.NewClient(*address, grpc.WithTransportCredentials(ce), grpc.WithAuthority(*serverName))

	// remember to close the tpm
	rwc.Close()
```

* `B)`:  `IdentityOptions.Certificates`

With this you need to acquire the TPM based certificate directly before initializing an `advancedtls` module

```golang
import (
	genericsigner "github.com/salrashid123/mtls-tokensource/signer"
	tpmsigner "github.com/salrashid123/signer/tpm"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
)
	// open the tpm
	rwc, err := openTPM(*tpmPath)
	defer rwc.Close()
	// get a reader
	rwr := transport.FromReadWriter(rwc)

	// read a TPM private key
	c, err := os.ReadFile(*tlsKey)
	key, err := keyfile.Decode(c)

	// acquire the H2 Primary key
	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)	

	//  Load the actual key object
	regenRSAKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primary.ObjectHandle,
			Name:   tpm2.TPM2BName(primary.Name),
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)


	// generate a TPM basic crypto.Signer
	tsigner, err := tpmsigner.NewTPMCrypto(&tpmsigner.TPM{
		TpmDevice: rwc,
		NamedHandle: &tpm2.NamedHandle{
			Handle: regenRSAKey.ObjectHandle,
			Name:   regenRSAKey.Name,
		},
		PublicCertFile: *tlsCert,
	})

	// use the signer and apply the public x509 for use in TLS sessions
	rs, err := genericsigner.NewGenericSignerTLS(&genericsigner.GenericSignerTLS{
		Signer:              tsigner,
		MtlsCertificateFile: *tlsCert,
	})

	// get the TLS certificate which includes the TPM signer
	tcrt, err := rs.TLSCertificate()

	// apply the certificate as an IdentityOption
	options := &advancedtls.Options{
		IdentityOptions: advancedtls.IdentityCertificateOptions{
			Certificates: []tls.Certificate{tcrt},
		},
	}
    // create an advancedTLS creds (clientcreds here)
	ce, err := advancedtls.NewClientCreds(options)

    // create a connection
	conn, err := grpc.NewClient(*address, grpc.WithTransportCredentials(ce))
```

---

### QuickStart

To see this working locally, see the `examples/` folder.

The default sample comes with a pre-configured TPM based EC key and a CA.

You will need to have `swtpm` and preferably `tpm2_tools` installed

First run the TPM

```bash
cd example/
sudo swtpm socket --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2
```

Now run the server

```bash
export GRPC_GO_LOG_SEVERITY_LEVEL=info
export GRPC_GO_LOG_VERBOSITY_LEVEL=99
export GODEBUG=http2debug=2

## only if you wanted to compile the proto
# /usr/local/bin/protoc --go_out=. \
#  --go_opt=paths=source_relative --go-grpc_opt=require_unimplemented_servers=false \
#   --experimental_allow_proto3_optional --include_source_info  \
#    --go-grpc_out=. --descriptor_set_out=echo/echo.proto.pb \
#     --go-grpc_opt=paths=source_relative echo/echo.proto

### start the local server
go run server/grpc_server.go \
    --grpcport 0.0.0.0:50051 \
    --clientCA=ca_scratchpad/ca/root-ca.crt \
    --tlsCert=ca_scratchpad/certs/server.crt \
    --tlsKey=ca_scratchpad/certs/server.key
```


test  `IdentityOptions.Certificates`

```bash
go run client_tpm_direct/grpc_client.go \
    --host 127.0.0.1:50051 \
    --rootCA=ca_scratchpad/ca/root-ca.crt \
    --servername=grpc.domain.com \
    --tlsCert=ca_scratchpad/certs/workload1.crt \
    --tlsKey=ca_scratchpad/certs/workload1.pem  \
    --tpm-path="127.0.0.1:2321"     
```

test  `IdentityOptions.IdentityProvider`

```bash
go run client_tpm_provider/grpc_client.go \
    --host 127.0.0.1:50051 \
    --rootCA=ca_scratchpad/ca/root-ca.crt \
    --servername=grpc.domain.com \
    --tlsCert=ca_scratchpad/certs/workload1.crt \
    --tlsKey=ca_scratchpad/certs/workload1.pem  \
    --tpm-path="127.0.0.1:2321"    
```

#### Appendix

###### Generate New CA and TPM Keys

If you would rather generate your own setup from scratch, you'll need to initialize a new ca service and swtpm from scratch

```bash
cd example/
rm -rf ca_scratchpad/

git clone https://github.com/salrashid123/ca_scratchpad.git
cd ca_scratchpad/

mkdir -p ca/root-ca/private ca/root-ca/db crl certs
chmod 700 ca/root-ca/private
cp /dev/null ca/root-ca/db/root-ca.db
cp /dev/null ca/root-ca/db/root-ca.db.attr
echo 01 > ca/root-ca/db/root-ca.crt.srl

openssl genpkey -algorithm ec -pkeyopt  ec_paramgen_curve:P-256 \
      -pkeyopt ec_param_enc:named_curve \
      -out ca/root-ca/private/root-ca.key

export SAN=single-root-ca

openssl req -new  -config single-root-ca.conf  -key ca/root-ca/private/root-ca.key \
   -out ca/root-ca.csr  

openssl ca -selfsign     -config single-root-ca.conf  \
   -in ca/root-ca.csr     -out ca/root-ca.crt  \
   -extensions root_ca_ext


### create server certificate
export NAME=server
export SAN="DNS:grpc.domain.com"

openssl genpkey -algorithm ec -pkeyopt  ec_paramgen_curve:P-256 \
      -pkeyopt ec_param_enc:named_curve \
      -out certs/$NAME.key

openssl req -new     -config server.conf \
  -out certs/$NAME.csr   \
  -key certs/$NAME.key \
  -subj "/C=US/O=Google/OU=Enterprise/CN=grpc.domain.com"

openssl ca \
    -config single-root-ca.conf \
    -in certs/$NAME.csr \
    -out certs/$NAME.crt \
    -extensions server_ext

### create pem client cert for testing
export NAME=client
export SAN="DNS:client.domain.com"

openssl genpkey -algorithm ec -pkeyopt  ec_paramgen_curve:P-256 \
      -pkeyopt ec_param_enc:named_curve \
      -out certs/$NAME.key

openssl req -new     -config client.conf \
  -out certs/$NAME.csr   \
  -key certs/$NAME.key \
  -subj "/C=US/O=Google/OU=Enterprise/CN=client.domain.com"

openssl ca \
    -config single-root-ca.conf \
    -in certs/$NAME.csr \
    -out certs/$NAME.crt \
    -extensions client_ext    

### start software TPM
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm  && \
   sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && \
    sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

## in a new window
export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"
export TPM2TSSENGINE_TCTI="swtpm:port=2321"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/  
# or wherever tpm2.so sits, eg /usr/lib/x86_64-linux-gnu/ossl-modules/tpm2.so
# export TSS2_LOG=esys+debug    

## create h2 primary
printf '\x00\x00' > certs/unique.dat
tpm2_createprimary -C o -G ecc -g sha256 \
  -c certs/rprimary.ctx \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u certs/unique.dat

### create key
export NAME=workload1
export SAN="URI:spiffie://domain/workload1"

tpm2_create -G ecc:ecdsa -g sha256 -u certs/rkey.pub -r certs/rkey.priv -C certs/rprimary.ctx
tpm2_flushcontext -t
tpm2_load -C certs/rprimary.ctx -u certs/rkey.pub -r certs/rkey.priv -c certs/rkey.ctx
tpm2_print -t TPM2B_PUBLIC certs/rkey.pub

### make it persistent
tpm2_evictcontrol -C o -c certs/rkey.ctx 0x81008001
tpm2_flushcontext -t

## convert the key public/private --> PEM
/usr/bin/tpm2tss-genkey -u certs/rkey.pub -r certs/rkey.priv certs/$NAME.pem 

openssl ec -provider tpm2  -provider default -in certs/$NAME.pem  --text

openssl req -provider tpm2 -provider default -new \
    -config client.conf \
    -out certs/$NAME.csr \
    -key certs/$NAME.pem \
    -subj "/C=US/O=Google/OU=Enterprise/CN=workload1"

openssl ca \
    -config single-root-ca.conf \
    -in certs/$NAME.csr \
    -out certs/$NAME.crt \
    -extensions client_ext
```