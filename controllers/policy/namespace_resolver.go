// Copyright 2020 Topicus Security BV
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"
	"regexp"

	"github.com/go-logr/logr"
	keyhubv1alpha1 "github.com/topicuskeyhub/keyhub-vault-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewNamespacePolicyResolver(client client.Client, log logr.Logger, policies []Policy) PolicyResolver {
	return &policyResolver{
		client:   client,
		log:      log,
		policies: policies,
	}
}

func (r *policyResolver) Resolve(secret *keyhubv1alpha1.KeyHubSecret) (*Policy, error) {
	namespace := secret.GetNamespace()

	var policyScore int = 999999999
	var matchedPolicy Policy
	for _, policy := range r.policies {
		if policy.Type != "namespace" {
			continue
		}

		if namespace == policy.Name {
			r.log.Info("Found exact match", "namespace", namespace, "ClientID", policy.Credentials.ClientID)
			return &policy, nil
		} else if policy.NameRegex != "" {
			found, err := regexp.MatchString(policy.NameRegex, namespace)
			if err != nil {
				return nil, err
			} else if found {
				r.log.Info("Found match based on regex", "namespace", namespace, "ClientID", policy.Credentials.ClientID)
				return &policy, nil
			}
		} else if policy.LabelSelector != "" {
			nsl := &corev1.NamespaceList{}
			ls, err := labels.Parse(policy.LabelSelector)
			if err != nil {
				return nil, err
			}
			opts := &client.ListOptions{
				LabelSelector: ls,
			}
			r.client.List(context.TODO(), nsl, opts)

			matchedNamespaces := len(nsl.Items)
			for _, ns := range nsl.Items {
				if ns.Name == namespace {
					if matchedNamespaces < policyScore {
						r.log.Info("Found match", "namespace", namespace, "ClientID", policy.Credentials.ClientID, "score", matchedNamespaces)
						policyScore = matchedNamespaces
						matchedPolicy = policy
						break
					} else if matchedNamespaces == policyScore {
						return nil, fmt.Errorf("Policy for client '%s' with label selector '%s' matches namespace '%s' with the same score as the policy for client '%s' with label selector '%s'", policy.Credentials.ClientID, policy.LabelSelector, namespace, matchedPolicy.Credentials.ClientID, matchedPolicy.LabelSelector)
					}
				}
			}
		}
	}

	if policyScore == 999999999 {
		return nil, fmt.Errorf("No credentials found for namespace %s", namespace)
	}

	return &matchedPolicy, nil
}
