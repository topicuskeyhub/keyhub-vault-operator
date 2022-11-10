// Copyright 2020 Topicus Security BV
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"bytes"
	"fmt"

	"github.com/topicuskeyhub/keyhub-vault-operator/api"
	keyhubv1alpha1 "github.com/topicuskeyhub/keyhub-vault-operator/api/v1alpha1"
	"github.com/topicuskeyhub/keyhub-vault-operator/controllers/vault"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (sb *secretBuilder) applyApachePasswordFile(ks *keyhubv1alpha1.KeyHubSecret, secret *corev1.Secret) error {
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}

	name := types.NamespacedName{
		Name:      ks.Name,
		Namespace: ks.Namespace,
	}

	needsUpdating := false
	var idxEntries []vault.VaultRecordWithGroup
	for _, ref := range ks.Spec.Data {
		idxEntry, found := sb.records[ref.Record]
		if !found {
			sb.log.Info("Missing KeyHub vault record", "keyhubsecret", name.String(), "key", ref.Name, "record", ref.Record)
			// event?
			return fmt.Errorf("Missing KeyHub vault record '%s'", ref.Record)
		}

		// Check whether or not the Secret needs updating
		if api.IsVaulRecordChanged(ks.Status.VaultRecordStatuses, &idxEntry.Record) {
			needsUpdating = true
		}

		idxEntries = append(idxEntries, idxEntry)
	}

	// FIXME: 'users' is the traefik key, get it from the key name
	secretDataChanged :=
		api.IsSecretKeyChanged(ks.Status.SecretKeyStatuses, secret.Data, "users")

	if !needsUpdating && !secretDataChanged {
		return nil
	}

	ks.Status.VaultRecordStatuses = []keyhubv1alpha1.VaultRecordStatus{}
	ks.Status.SecretKeyStatuses = []keyhubv1alpha1.SecretKeyStatus{}

	var credentials bytes.Buffer
	for _, idxEntry := range idxEntries {
		//		sb.log.Info("Syncing KeyHub vault record", "keyhubsecret", fmt.Sprintf("%s/%s", ks.Namespace, ks.Name))
		record, err := sb.retriever.Get(idxEntry)
		if err != nil {
			return err
		}

		if len(record.Username) == 0 {
			return fmt.Errorf("Username field of record %s is empty", idxEntry.Record.UUID)
		}

		if record.Password() == nil {
			return fmt.Errorf("Password field of record %s is empty", idxEntry.Record.UUID)
		}

		pwdHash, err := bcrypt.GenerateFromPassword([]byte(*record.Password()), bcrypt.DefaultCost)
		if err != nil {
			continue
		}

		credentials.WriteString(record.Username)
		credentials.WriteString(":")
		credentials.Write(pwdHash)
		credentials.WriteString("\n")

		api.SetVaultRecordStatus(&ks.Status.VaultRecordStatuses, record)
	}

	secret.Data = map[string][]byte{
		"users": credentials.Bytes(),
	}

	err := api.SetSecretKeyStatus(&ks.Status.SecretKeyStatuses, "users", secret.Data["users"])
	if err != nil {
		// event + err @ end
		return err
	}

	return nil
}
