// Copyright 2020 Topicus Security BV
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"github.com/go-logr/logr"
	keyhubv1alpha1 "github.com/topicuskeyhub/keyhub-vault-operator/api/v1alpha1"
	"github.com/topicuskeyhub/keyhub-vault-operator/controllers/vault"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type SecretBuilder interface {
	Build(ks *keyhubv1alpha1.KeyHubSecret, secret *corev1.Secret) error
}

type secretBuilder struct {
	client    client.Client
	log       logr.Logger
	records   map[string]vault.VaultRecordWithGroup
	retriever vault.VaultSecretRetriever
}

func NewSecretBuilder(client client.Client, log logr.Logger, records map[string]vault.VaultRecordWithGroup, retriever vault.VaultSecretRetriever) SecretBuilder {
	return &secretBuilder{
		client:    client,
		log:       log,
		records:   records,
		retriever: retriever,
	}
}

func (sb *secretBuilder) Build(ks *keyhubv1alpha1.KeyHubSecret, secret *corev1.Secret) error {
	// Apply labels and annotations
	sb.applyLabels(ks, secret)
	sb.applyAnnotations(ks, secret)

	// Secret type is immutable, k8s will complain if it changes
	secret.Type = ks.Spec.Template.Type
	if secret.Type == "" {
		secret.Type = corev1.SecretTypeOpaque
	}
	switch secret.Type {
	case corev1.SecretTypeBasicAuth:
		return sb.applyBasicAuthSecretData(ks, secret)
	case corev1.SecretTypeSSHAuth:
		return sb.applySSHAuthSecretData(ks, secret)
	case corev1.SecretTypeTLS:
		return sb.applyTLSSecretData(ks, secret)
	case keyhubv1alpha1.SecretTypeApachePasswordFile:
		return sb.applyApachePasswordFile(ks, secret)
	default:
		return sb.applyOpaqueSecretData(ks, secret)
	}
}

func (sb *secretBuilder) applyLabels(ks *keyhubv1alpha1.KeyHubSecret, secret *corev1.Secret) {
	if secret.GetLabels() == nil {
		secret.SetLabels(make(map[string]string))
	}

	sb.applyStandardLabels(ks, secret)

	for label, value := range ks.Spec.Template.Metadata.Labels {
		secret.GetLabels()[label] = value
	}
}

func (sb *secretBuilder) applyStandardLabels(ks *keyhubv1alpha1.KeyHubSecret, secret *corev1.Secret) {
	for label, value := range ks.GetLabels() {
		switch label {
		case "app.kubernetes.io/name":
			fallthrough
		case "helm.sh/chart":
			fallthrough
		case "app.kubernetes.io/managed-by":
			fallthrough
		case "app.kubernetes.io/instance":
			fallthrough
		case "app.kubernetes.io/version":
			fallthrough
		case "app.kubernetes.io/component":
			fallthrough
		case "app.kubernetes.io/part-of":
			secret.GetLabels()[label] = value
		}
	}
}

func (sb *secretBuilder) applyAnnotations(ks *keyhubv1alpha1.KeyHubSecret, secret *corev1.Secret) {
	if secret.GetAnnotations() == nil {
		secret.SetAnnotations(make(map[string]string))
	}
	for ann, value := range ks.Spec.Template.Metadata.Annotations {
		secret.GetAnnotations()[ann] = value
	}
}
