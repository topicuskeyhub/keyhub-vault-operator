package secret

import (
	"fmt"

	"github.com/topicusonderwijs/keyhub-vault-operator/api"
	keyhubv1alpha1 "github.com/topicusonderwijs/keyhub-vault-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

func (sb *secretBuilder) applyBasicAuthSecretData(ks *keyhubv1alpha1.KeyHubSecret, secret *corev1.Secret) error {
	if len(ks.Spec.Data) != 1 {
		return fmt.Errorf("Expected one key for basic authentication, found %d", len(ks.Spec.Data))
	}

	ref := ks.Spec.Data[0]

	idxEntry, ok := sb.records[ref.Record]
	if !ok {
		return fmt.Errorf("Record %s not found for key %s", ref.Record, ref.Name)
	}

	// Check whether or not the Secret needs updating
	recordChanged := api.IsVaulRecordChanged(ks.Status.VaultRecordStatuses, &idxEntry.Record)
	secretDataChanged := api.IsSecretKeyChanged(ks.Status.SecretKeyStatuses, secret.Data, corev1.BasicAuthUsernameKey)
	if !recordChanged && !secretDataChanged {
		return nil
	}

	record, err := sb.retriever.Get(idxEntry)
	if err != nil {
		return err
	}

	if len(record.Username) == 0 {
		return fmt.Errorf("Username field of record %s is empty", ref.Record)
	}

	if len(record.Password()) == 0 {
		return fmt.Errorf("Password field of record %s is empty", ref.Record)
	}

	secret.Data = map[string][]byte{
		corev1.BasicAuthUsernameKey: []byte(record.Username),
		corev1.BasicAuthPasswordKey: []byte(record.Password()),
	}

	ks.Status.VaultRecordStatuses = []keyhubv1alpha1.VaultRecordStatus{}
	ks.Status.SecretKeyStatuses = []keyhubv1alpha1.SecretKeyStatus{}
	api.SetVaultRecordStatus(&ks.Status.VaultRecordStatuses, record)
	err = api.SetSecretKeyStatus(&ks.Status.SecretKeyStatuses, corev1.BasicAuthUsernameKey, secret.Data[corev1.BasicAuthUsernameKey])
	if err != nil {
		// event + err @ end
		return err
	}
	err = api.SetSecretKeyStatus(&ks.Status.SecretKeyStatuses, corev1.BasicAuthPasswordKey, secret.Data[corev1.BasicAuthPasswordKey])
	if err != nil {
		// event + err @ end
		return err
	}

	return nil
}
