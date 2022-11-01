// Copyright 2020 Topicus Security BV
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/patrickmn/go-cache"
	keyhub "github.com/topicuskeyhub/go-keyhub"
	keyhubv1alpha1 "github.com/topicuskeyhub/keyhub-vault-operator/api/v1alpha1"
	"github.com/topicuskeyhub/keyhub-vault-operator/controllers/settings"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type PolicyEngine interface {
	GetClient(secret *keyhubv1alpha1.KeyHubSecret) (*keyhub.Client, error)
	Flush()
}

type policyEngine struct {
	client          client.Client
	log             logr.Logger
	settingsManager settings.SettingsManager
	policyCache     PolicyCache
	clientCache     *cache.Cache
	mutex           *sync.Mutex
}

func NewPolicyEngine(client client.Client, log logr.Logger, settingsMgr settings.SettingsManager) PolicyEngine {
	policyLoader := NewPolicyLoader(log, settingsMgr)
	return &policyEngine{
		client:          client,
		log:             log,
		settingsManager: settingsMgr,
		policyCache:     NewPolicyCache(log, policyLoader),
		clientCache:     cache.New(10*time.Minute, 15*time.Minute),
		mutex:           &sync.Mutex{},
	}
}

func (pe *policyEngine) GetClient(secret *keyhubv1alpha1.KeyHubSecret) (*keyhub.Client, error) {
	pe.log.Info("Policy based client lookup", "KeyHubSecret", fmt.Sprintf("%s/%s", secret.Namespace, secret.Name))
	policies, err := pe.policyCache.GetPolicies()
	if err != nil {
		return nil, err
	}

	policy, err := pe.match(policies, secret)
	if err != nil {
		return nil, err
	}

	clientID := policy.Credentials.ClientID
	client, found := pe.clientCache.Get(clientID)
	if !found {
		pe.mutex.Lock()
		defer pe.mutex.Unlock()

		client, found = pe.clientCache.Get(clientID)
		if !found {
			settings, err := pe.settingsManager.GetSettings()
			if err != nil {
				return nil, err
			}

			client, err = keyhub.NewClient(http.DefaultClient, settings.URI, policy.Credentials.ClientID, policy.Credentials.ClientSecret)
			if err != nil {
				return nil, err
			}

			pe.clientCache.SetDefault(clientID, client)
		}
	}

	pe.log.Info("Client with matching policy found", "client", clientID)

	return client.(*keyhub.Client), nil
}

func (pe *policyEngine) match(policies []Policy, secret *keyhubv1alpha1.KeyHubSecret) (*Policy, error) {
	resolver := NewNamespacePolicyResolver(
		pe.client,
		pe.log.WithName("NamespacePolicyResolver"),
		policies,
	)

	return resolver.Resolve(secret)
}

func (pe *policyEngine) Flush() {
	pe.policyCache.Flush()
}
