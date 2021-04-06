package api

import (
	"encoding/base64"

	"github.com/topicuskeyhub/go-keyhub"
	"github.com/topicusonderwijs/keyhub-vault-operator/api/v1alpha1"
	"golang.org/x/crypto/bcrypt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetVaultRecordStatus sets the corresponding status in statuses to the
// new status based on record.
// statuses must be non-nil.
func SetVaultRecordStatus(statuses *[]v1alpha1.VaultRecordStatus, record *keyhub.VaultRecord) {
	if statuses == nil {
		return
	}

	newStatus := v1alpha1.VaultRecordStatus{
		RecordID:       record.UUID,
		Name:           record.Name,
		LastModifiedAt: metav1.NewTime(record.LastModifiedAt()),
	}

	existingStatus := FindVaultRecordStatus(*statuses, newStatus.RecordID)
	if existingStatus == nil {
		*statuses = append(*statuses, newStatus)
		return
	}

	existingStatus.Name = newStatus.Name
	existingStatus.LastModifiedAt = newStatus.LastModifiedAt
}

// FindVaultRecordStatus finds the recordID in statuses.
func FindVaultRecordStatus(statuses []v1alpha1.VaultRecordStatus, recordID string) *v1alpha1.VaultRecordStatus {
	for i := range statuses {
		if statuses[i].RecordID == recordID {
			return &statuses[i]
		}
	}

	return nil
}

// SetSecretKeyStatus sets the corresponding status in statuses to newStatus.
// statuses must be non-nil.
func SetSecretKeyStatus(statuses *[]v1alpha1.SecretKeyStatus, key string, value []byte) error {
	if statuses == nil {
		return nil
	}

	encValue := make([]byte, base64.StdEncoding.EncodedLen(len(value)))
	base64.StdEncoding.Encode(encValue, value)
	hash, err := bcrypt.GenerateFromPassword(encValue, bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	newStatus := v1alpha1.SecretKeyStatus{
		Key:  key,
		Hash: hash,
	}

	existingStatus := FindSecretKeyStatus(*statuses, newStatus.Key)
	if existingStatus == nil {
		*statuses = append(*statuses, newStatus)
		return nil
	}

	existingStatus.Hash = newStatus.Hash

	return nil
}

// FindSecretKeyStatus finds the key in statuses.
func FindSecretKeyStatus(statuses []v1alpha1.SecretKeyStatus, key string) *v1alpha1.SecretKeyStatus {
	for i := range statuses {
		if statuses[i].Key == key {
			return &statuses[i]
		}
	}

	return nil
}
