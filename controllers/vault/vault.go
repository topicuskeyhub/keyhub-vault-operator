package vault

import (
	"github.com/go-logr/logr"
	keyhub "github.com/topicuskeyhub/go-keyhub"
)

type VaultSecretRetriever interface {
	Get(record VaultRecordWithGroup) (*keyhub.VaultRecord, error)
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

func (r *vaultSecretRetriever) Get(idxEntry VaultRecordWithGroup) (*keyhub.VaultRecord, error) {
	return r.client.Vaults.GetRecord(
		&idxEntry.Group,
		idxEntry.Record.UUID,
		keyhub.RecordOptions{Secret: true, Audit: true},
	)
}