package secret

import (
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/topicusonderwijs/keyhub-vault-operator/api"
	keyhubv1alpha1 "github.com/topicusonderwijs/keyhub-vault-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (sb *secretBuilder) applyOpaqueSecretData(ks *keyhubv1alpha1.KeyHubSecret, secret *corev1.Secret) error {
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}

	name := types.NamespacedName{
		Name:      ks.Name,
		Namespace: ks.Namespace,
	}

	// Remove obsolete keys
	keysToRemove := make(map[string]struct{})
	recordStatusesToRemove := make(map[string]struct{})
	for _, status := range ks.Status.SecretKeyStatuses {
		keysToRemove[status.Key] = struct{}{}
	}
	for _, status := range ks.Status.VaultRecordStatuses {
		recordStatusesToRemove[status.RecordID] = struct{}{}
	}
	for _, ref := range ks.Spec.Data {
		delete(keysToRemove, ref.Name)
		delete(recordStatusesToRemove, ref.Record)
	}
	for key := range keysToRemove {
		delete(secret.Data, key)
	}
	ks.Status.SecretKeyStatuses = api.DeleteSecretKeyStatus(ks.Status.SecretKeyStatuses, keysToRemove)
	for status := range recordStatusesToRemove {
		ks.Status.VaultRecordStatuses = api.DeleteVaultRecordStatus(ks.Status.VaultRecordStatuses, status)
	}

	for _, ref := range ks.Spec.Data {
		idxEntry, found := sb.records[ref.Record]
		if !found {
			sb.log.Info("Missing KeyHub vault record", "keyhubsecret", name.String(), "key", ref.Name, "record", ref.Record)
			// event?
			continue
		}

		// Check whether or not the Secret needs updating
		recordChanged := api.IsVaulRecordChanged(ks.Status.VaultRecordStatuses, &idxEntry.Record)
		secretDataChanged :=
			api.IsSecretKeyChanged(ks.Status.SecretKeyStatuses, secret.Data, ref.Name)
		if !recordChanged && !secretDataChanged {
			continue
		}

		sb.log.Info("Syncing KeyHub vault record", "keyhubsecret", name.String(), "record", idxEntry.Record.UUID)

		record, err := sb.retriever.Get(idxEntry)
		if err != nil {
			// event + err @ end
			continue
			// return err
		}

		if ref.Property == "username" {
			secret.Data[ref.Name] = []byte(record.Username)
		} else if ref.Property == "password" || ref.Property == "" {
			pwd := []byte("")
			if record.Password() != nil {
				pwd = []byte(*record.Password())
			}
			if ref.Format == "bcrypt" {
				secret.Data[ref.Name], err = bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
				if err != nil {
					continue
				}
			} else {
				secret.Data[ref.Name] = pwd
			}
		} else if ref.Property == "link" {
			secret.Data[ref.Name] = []byte(record.URL)
		} else if ref.Property == "file" {
			file := []byte{}
			if record.File() != nil {
				file = *record.File()
			}
			secret.Data[ref.Name] = file
		} else if ref.Property == "lastModifiedAt" {
			secret.Data[ref.Name] = []byte(record.LastModifiedAt().UTC().Format(time.RFC3339))
		} else {
			// TODO: report to crd status, just skipping the key, no error
			sb.log.Info("Unsupported property", "property", ref.Property)
			continue
		}

		api.SetVaultRecordStatus(&ks.Status.VaultRecordStatuses, record)
		err = api.SetSecretKeyStatus(&ks.Status.SecretKeyStatuses, ref.Name, secret.Data[ref.Name])
		if err != nil {
			// event + err @ end
			continue
		}
	}

	return nil
}
