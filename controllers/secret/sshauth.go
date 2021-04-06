package secret

import (
	"fmt"

	"github.com/topicusonderwijs/keyhub-vault-operator/api"
	keyhubv1alpha1 "github.com/topicusonderwijs/keyhub-vault-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

func (sb *secretBuilder) applySSHAuthSecretData(ks *keyhubv1alpha1.KeyHubSecret, secret *corev1.Secret) error {
	if len(ks.Spec.Data) != 1 {
		return fmt.Errorf("Expected one key for SSH authentication, found %d", len(ks.Spec.Data))
	}

	ref := ks.Spec.Data[0]
	if ref.Name != "key" {
		return fmt.Errorf("Invalid name '%s', only 'key' is allowed for SSH authentication", ref.Name)
	}

	idxEntry, ok := sb.records[ref.Record]
	if !ok {
		return fmt.Errorf("Record %s not found for key %s", ref.Record, ref.Name)
	}

	// checks

	record, err := sb.retriever.Get(idxEntry)
	if err != nil {
		return err
	}

	if len(record.File()) == 0 {
		return fmt.Errorf("Missing file for record %s", ref.Record)
	}

	secret.Data = map[string][]byte{
		corev1.SSHAuthPrivateKey: record.File(),
	}

	api.SetVaultRecordStatus(&ks.Status.VaultRecordStatuses, record)
	err = api.SetSecretKeyStatus(&ks.Status.SecretKeyStatuses, corev1.SSHAuthPrivateKey, secret.Data[corev1.SSHAuthPrivateKey])
	if err != nil {
		// event + err @ end
		return err
	}

	return nil
}
