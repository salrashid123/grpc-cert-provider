package tpm

import (
	"encoding/json"
	"fmt"

	"google.golang.org/grpc/credentials/tls/certprovider"
)

const (
	// PluginName is the name of the TPM plugin.
	PluginName = "tpm_plugin"
)

func init() {
	certprovider.Register(&pluginBuilder{})
}

type pluginBuilder struct{}

func (p *pluginBuilder) ParseConfig(c any) (*certprovider.BuildableConfig, error) {
	data, ok := c.(json.RawMessage)
	if !ok {
		return nil, fmt.Errorf("meshca: unsupported config type: %T", c)
	}
	opts, err := pluginConfigFromJSON(data)
	if err != nil {
		return nil, err
	}
	return certprovider.NewBuildableConfig(PluginName, opts.canonical(), func(certprovider.BuildOptions) certprovider.Provider {
		return newProvider(opts)
	}), nil
}

func (p *pluginBuilder) Name() string {
	return PluginName
}

func pluginConfigFromJSON(jd json.RawMessage) (Options, error) {
	cfg := &struct {
		CertificateFile string `json:"certificate_file,omitempty"`
		PrivateKeyFile  string `json:"private_key_file,omitempty"`
	}{}
	if err := json.Unmarshal(jd, cfg); err != nil {
		return Options{}, fmt.Errorf("pemfile: json.Unmarshal(%s) failed: %v", string(jd), err)
	}

	opts := Options{
		CertFile: cfg.CertificateFile,
		KeyFile:  cfg.PrivateKeyFile,
	}

	if err := opts.validate(); err != nil {
		return Options{}, err
	}
	return opts, nil
}
