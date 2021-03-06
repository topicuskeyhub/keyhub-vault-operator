// Copyright 2020 Topicus Security BV
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/patrickmn/go-cache"
)

type PolicyCache interface {
	GetPolicies() ([]Policy, error)
	Flush()
}

type policyCache struct {
	log    logr.Logger
	loader PolicyLoader
	cache  *cache.Cache
	mutex  *sync.Mutex
}

func NewPolicyCache(log logr.Logger, loader PolicyLoader) PolicyCache {
	return &policyCache{
		log:    log,
		loader: loader,
		cache:  cache.New(2*time.Hour, 30*time.Minute),
		mutex:  &sync.Mutex{},
	}
}

func (pc *policyCache) GetPolicies() ([]Policy, error) {
	policies, found := pc.cache.Get("policies")
	if !found {
		pc.mutex.Lock()
		defer pc.mutex.Unlock()

		policies, found = pc.cache.Get("policies")
		if !found {
			policiesPtr, err := pc.loader.Load()
			if err != nil {
				return nil, err
			}
			policies = *policiesPtr
			pc.cache.SetDefault("policies", policies)
		}
	}
	return policies.([]Policy), nil
}

func (pc *policyCache) Flush() {
	pc.cache.Flush()
}
