package policy

import (
	"github.com/go-logr/logr"
	keyhubv1alpha1 "github.com/topicusonderwijs/keyhub-vault-operator/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Policy struct {
	policy
	Credentials ClientCredentials
}

type ClientCredentials struct {
	ClientID     string
	ClientSecret string
}

type policy struct {
	Type          string `yaml:"type"`
	Name          string `yaml:"name,omitempty"`
	LabelSelector string `yaml:"labelSelector,omitempty"`
}

type PolicyResolver interface {
	Resolve(secret *keyhubv1alpha1.KeyHubSecret) (*Policy, error)
}

type policyResolver struct {
	client   client.Client
	log      logr.Logger
	policies []Policy
}
