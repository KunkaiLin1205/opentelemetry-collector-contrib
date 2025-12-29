// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafka // import "github.com/open-telemetry/opentelemetry-collector-contrib/internal/kafka"

import (
	"context"
	"fmt"

	"github.com/IBM/sarama"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	// Default OAuth scope for GCP
	defaultScope = "https://www.googleapis.com/auth/cloud-platform"
)

// gcpMetadataTokenProvider implements sarama.AccessTokenProvider
// for GCP metadata server authentication (supports GKE Workload Identity, GCE, etc.).
type gcpMetadataTokenProvider struct {
	tokenSource oauth2.TokenSource
}

// Token implements sarama.AccessTokenProvider interface.
func (p *gcpMetadataTokenProvider) Token() (*sarama.AccessToken, error) {
	token, err := p.tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token from GCP: %w", err)
	}

	return &sarama.AccessToken{
		Token:      token.AccessToken,
		Extensions: map[string]string{},
	}, nil
}

// staticTokenProvider implements sarama.AccessTokenProvider for static tokens.
type staticTokenProvider struct {
	token string
}

// Token implements sarama.AccessTokenProvider interface.
func (p *staticTokenProvider) Token() (*sarama.AccessToken, error) {
	return &sarama.AccessToken{
		Token:      p.token,
		Extensions: map[string]string{},
	}, nil
}

// newOAuthBearerTokenProvider creates a new token provider based on the configuration.
func newOAuthBearerTokenProvider(config OAuthBearerConfig) (sarama.AccessTokenProvider, error) {
	switch config.TokenProvider {
	case "gcp_metadata", "gke_workload_identity", "":
		// Use Google's official oauth2 library to get tokens from GCP metadata server
		// This supports GKE Workload Identity, GCE, and other GCP environments
		// google.DefaultTokenSource automatically:
		// - Uses Workload Identity in GKE when KSA is bound to GCP SA
		// - Falls back to GCE metadata server in GCE
		// - Supports other GCP authentication methods
		scope := config.Scope
		if scope == "" {
			scope = defaultScope
		}

		ctx := context.Background()
		tokenSource, err := google.DefaultTokenSource(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCP token source: %w", err)
		}

		return &gcpMetadataTokenProvider{
			tokenSource: tokenSource,
		}, nil
	case "static":
		if config.Token == "" {
			return nil, fmt.Errorf("token is required when token_provider is 'static'")
		}
		return &staticTokenProvider{
			token: config.Token,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported token_provider: %s. Supported values: 'gcp_metadata', 'gke_workload_identity', 'static'", config.TokenProvider)
	}
}
