// Copyright 2020 Topicus Security BV
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"github.com/go-logr/logr"
	"github.com/google/uuid"
	keyhub "github.com/topicuskeyhub/go-keyhub"
	keyhubmodel "github.com/topicuskeyhub/go-keyhub/model"
	"github.com/topicuskeyhub/keyhub-vault-operator/controllers/metrics"
)

type VaultSecretRetriever interface {
	Get(record VaultRecordWithGroup) (*keyhubmodel.VaultRecord, error)
}

type vaultSecretRetriever struct {
	log    logr.Logger
	client *keyhub.Client
}

func NewVaultSecretRetriever(log logr.Logger, client *keyhub.Client) VaultSecretRetriever {
	return &vaultSecretRetriever{
		log:    log,
		client: client,
	}
}

func (r *vaultSecretRetriever) Get(idxEntry VaultRecordWithGroup) (*keyhubmodel.VaultRecord, error) {
	metrics.KeyHubApiRequests.WithLabelValues("vault", "get").Inc()
	uuid, err := uuid.Parse(idxEntry.Record.UUID)
	if err != nil {
		return nil, err
	}
	return r.client.Vaults.GetByUUID(
		&idxEntry.Group,
		uuid,
		&keyhubmodel.VaultRecordAdditionalQueryParams{Secret: true, Audit: true},
	)
}
