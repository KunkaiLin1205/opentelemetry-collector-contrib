// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafka // import "github.com/open-telemetry/opentelemetry-collector-contrib/internal/kafka"

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/IBM/sarama"
	"go.opentelemetry.io/collector/config/configtls"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/kafka/awsmsk"
)

// Authentication defines authentication.
type Authentication struct {
	PlainText *PlainTextConfig        `mapstructure:"plain_text"`
	SASL      *SASLConfig             `mapstructure:"sasl"`
	TLS       *configtls.ClientConfig `mapstructure:"tls"`
	Kerberos  *KerberosConfig         `mapstructure:"kerberos"`
}

// PlainTextConfig defines plaintext authentication.
type PlainTextConfig struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// SASLConfig defines the configuration for the SASL authentication.
type SASLConfig struct {
	// Username to be used on authentication
	Username string `mapstructure:"username"`
	// Password to be used on authentication
	Password string `mapstructure:"password"`
	// SASL Mechanism to be used, possible values are: (PLAIN, AWS_MSK_IAM, SCRAM-SHA-256, SCRAM-SHA-512, OAUTHBEARER).
	Mechanism string `mapstructure:"mechanism"`
	// SASL Protocol Version to be used, possible values are: (0, 1). Defaults to 0.
	Version int `mapstructure:"version"`

	AWSMSK AWSMSKConfig `mapstructure:"aws_msk"`

	// OAuthBearer defines the configuration for OAUTHBEARER authentication.
	OAuthBearer OAuthBearerConfig `mapstructure:"oauthbearer"`
}

// AWSMSKConfig defines the additional SASL authentication
// measures needed to use AWS_MSK_IAM mechanism
type AWSMSKConfig struct {
	// Region is the AWS region the MSK cluster is based in
	Region string `mapstructure:"region"`
	// BrokerAddr is the client is connecting to in order to perform the auth required
	BrokerAddr string `mapstructure:"broker_addr"`
}

// OAuthBearerConfig defines the configuration for OAUTHBEARER authentication.
type OAuthBearerConfig struct {
	// TokenProvider is the token provider type. Supported values: "gcp_metadata", "gke_workload_identity", "static".
	// When set to "gcp_metadata" or "gke_workload_identity", the token will be fetched from GCP metadata server
	// using Google's official oauth2 library. This supports GKE Workload Identity, GCE, and other GCP environments.
	// "gke_workload_identity" is an alias for "gcp_metadata" for backward compatibility.
	// When set to "static", the token will be read from the Token field.
	TokenProvider string `mapstructure:"token_provider"`
	// Token is the static OAuth bearer token. Only used when TokenProvider is "static".
	Token string `mapstructure:"token"`
	// ServiceAccountEmail is the GCP service account email (currently not used, reserved for future use).
	// When using GKE Workload Identity, the service account is automatically determined from the
	// Kubernetes Service Account binding via google.DefaultTokenSource. This field is kept for backward compatibility.
	ServiceAccountEmail string `mapstructure:"service_account_email"`
	// Scope is the OAuth scope to request. Only used when TokenProvider is "gcp_metadata" or "gke_workload_identity".
	// Defaults to "https://www.googleapis.com/auth/cloud-platform".
	Scope string `mapstructure:"scope"`
}

// KerberosConfig defines kerberos configuration.
type KerberosConfig struct {
	ServiceName     string `mapstructure:"service_name"`
	Realm           string `mapstructure:"realm"`
	UseKeyTab       bool   `mapstructure:"use_keytab"`
	Username        string `mapstructure:"username"`
	Password        string `mapstructure:"password" json:"-"`
	ConfigPath      string `mapstructure:"config_file"`
	KeyTabPath      string `mapstructure:"keytab_file"`
	DisablePAFXFAST bool   `mapstructure:"disable_fast_negotiation"`
}

// ConfigureAuthentication configures authentication in sarama.Config.
func ConfigureAuthentication(config Authentication, saramaConfig *sarama.Config) error {
	if config.PlainText != nil {
		configurePlaintext(*config.PlainText, saramaConfig)
	}
	if config.TLS != nil {
		if err := configureTLS(*config.TLS, saramaConfig); err != nil {
			return err
		}
	}
	if config.SASL != nil {
		if err := configureSASL(*config.SASL, saramaConfig); err != nil {
			return err
		}
	}

	if config.Kerberos != nil {
		configureKerberos(*config.Kerberos, saramaConfig)
	}
	return nil
}

func configurePlaintext(config PlainTextConfig, saramaConfig *sarama.Config) {
	saramaConfig.Net.SASL.Enable = true
	saramaConfig.Net.SASL.User = config.Username
	saramaConfig.Net.SASL.Password = config.Password
}

func configureSASL(config SASLConfig, saramaConfig *sarama.Config) error {
	saramaConfig.Net.SASL.Enable = true

	switch config.Mechanism {
	case "OAUTHBEARER":
		tokenProvider, err := newOAuthBearerTokenProvider(config.OAuthBearer)
		if err != nil {
			return fmt.Errorf("failed to create OAuth bearer token provider: %w", err)
		}
		saramaConfig.Net.SASL.Mechanism = sarama.SASLTypeOAuth
		saramaConfig.Net.SASL.TokenProvider = tokenProvider
	case "SCRAM-SHA-512":
		if config.Username == "" {
			return fmt.Errorf("username have to be provided")
		}
		if config.Password == "" {
			return fmt.Errorf("password have to be provided")
		}
		saramaConfig.Net.SASL.User = config.Username
		saramaConfig.Net.SASL.Password = config.Password
		saramaConfig.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient { return &XDGSCRAMClient{HashGeneratorFcn: sha512.New} }
		saramaConfig.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512
	case "SCRAM-SHA-256":
		if config.Username == "" {
			return fmt.Errorf("username have to be provided")
		}
		if config.Password == "" {
			return fmt.Errorf("password have to be provided")
		}
		saramaConfig.Net.SASL.User = config.Username
		saramaConfig.Net.SASL.Password = config.Password
		saramaConfig.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient { return &XDGSCRAMClient{HashGeneratorFcn: sha256.New} }
		saramaConfig.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
	case "PLAIN":
		if config.Username == "" {
			return fmt.Errorf("username have to be provided")
		}
		if config.Password == "" {
			return fmt.Errorf("password have to be provided")
		}
		saramaConfig.Net.SASL.User = config.Username
		saramaConfig.Net.SASL.Password = config.Password
		saramaConfig.Net.SASL.Mechanism = sarama.SASLTypePlaintext
	case "AWS_MSK_IAM":
		if config.Username == "" {
			return fmt.Errorf("username have to be provided")
		}
		if config.Password == "" {
			return fmt.Errorf("password have to be provided")
		}
		saramaConfig.Net.SASL.User = config.Username
		saramaConfig.Net.SASL.Password = config.Password
		saramaConfig.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
			return awsmsk.NewIAMSASLClient(config.AWSMSK.BrokerAddr, config.AWSMSK.Region, saramaConfig.ClientID)
		}
		saramaConfig.Net.SASL.Mechanism = awsmsk.Mechanism
	default:
		return fmt.Errorf(`invalid SASL Mechanism %q: can be either "PLAIN", "AWS_MSK_IAM", "SCRAM-SHA-256", "SCRAM-SHA-512" or "OAUTHBEARER"`, config.Mechanism)
	}

	switch config.Version {
	case 0:
		saramaConfig.Net.SASL.Version = sarama.SASLHandshakeV0
	case 1:
		saramaConfig.Net.SASL.Version = sarama.SASLHandshakeV1
	default:
		return fmt.Errorf(`invalid SASL Protocol Version %d: can be either 0 or 1`, config.Version)
	}

	return nil
}

func configureTLS(config configtls.ClientConfig, saramaConfig *sarama.Config) error {
	tlsConfig, err := config.LoadTLSConfig(context.Background())
	if err != nil {
		return fmt.Errorf("error loading tls config: %w", err)
	}
	saramaConfig.Net.TLS.Enable = true
	saramaConfig.Net.TLS.Config = tlsConfig
	return nil
}

func configureKerberos(config KerberosConfig, saramaConfig *sarama.Config) {
	saramaConfig.Net.SASL.Mechanism = sarama.SASLTypeGSSAPI
	saramaConfig.Net.SASL.Enable = true
	if config.UseKeyTab {
		saramaConfig.Net.SASL.GSSAPI.KeyTabPath = config.KeyTabPath
		saramaConfig.Net.SASL.GSSAPI.AuthType = sarama.KRB5_KEYTAB_AUTH
	} else {
		saramaConfig.Net.SASL.GSSAPI.AuthType = sarama.KRB5_USER_AUTH
		saramaConfig.Net.SASL.GSSAPI.Password = config.Password
	}
	saramaConfig.Net.SASL.GSSAPI.KerberosConfigPath = config.ConfigPath
	saramaConfig.Net.SASL.GSSAPI.Username = config.Username
	saramaConfig.Net.SASL.GSSAPI.Realm = config.Realm
	saramaConfig.Net.SASL.GSSAPI.ServiceName = config.ServiceName
	saramaConfig.Net.SASL.GSSAPI.DisablePAFXFAST = config.DisablePAFXFAST
}
