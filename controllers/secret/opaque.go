package secret

import (
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/topicusonderwijs/keyhub-vault-operator/api"
	keyhubv1alpha1 "github.com/topicusonderwijs/keyhub-vault-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

func (sb *secretBuilder) applyOpaqueSecretData(ks *keyhubv1alpha1.KeyHubSecret, secret *corev1.Secret) error {
	// data := make(map[string][]byte)
	// missing := false
	sb.log.Info("opaque secret")
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	for _, ref := range ks.Spec.Data {
		idxEntry, found := sb.records[ref.Record]
		if !found {
			sb.log.Info("record missing", "uuid", ref.Record)
			continue
		}
		// if !ok {
		// 	// event + err @ end
		// 	continue
		// 	// return fmt.Errorf("Record %s not found for key %s", ref.Record, ref.Name)
		// }

		record, err := sb.retriever.Get(idxEntry)
		if err != nil {
			// event + err @ end
			continue
			// return err
		}

		if ref.Property == "username" {
			secret.Data[ref.Name] = []byte(record.Username)
		} else if ref.Property == "password" || ref.Property == "" {
			if ref.Format == "bcrypt" {
				secret.Data[ref.Name], err = bcrypt.GenerateFromPassword([]byte(record.Password()), bcrypt.DefaultCost)
				if err != nil {
					continue
				}
			} else {
				secret.Data[ref.Name] = []byte(record.Password())
			}
		} else if ref.Property == "link" {
			secret.Data[ref.Name] = []byte(record.URL)
		} else if ref.Property == "file" {
			secret.Data[ref.Name] = record.File()
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
