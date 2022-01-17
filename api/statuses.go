package api

import (
	"encoding/base64"

	keyhubmodel "github.com/topicuskeyhub/go-keyhub/model"
	"github.com/topicusonderwijs/keyhub-vault-operator/api/v1alpha1"
	"golang.org/x/crypto/bcrypt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetVaultRecordStatus sets the corresponding status in statuses to the
// new status based on record.
// statuses must be non-nil.
func SetVaultRecordStatus(statuses *[]v1alpha1.VaultRecordStatus, record *keyhubmodel.VaultRecord) {
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

func DeleteVaultRecordStatus(statuses []v1alpha1.VaultRecordStatus, recordID string) []v1alpha1.VaultRecordStatus {
	var d int
	for i := range statuses {
		if statuses[i].RecordID == recordID {
			d = i
			break
		}
	}

	return append(statuses[:d], statuses[d+1:]...)
}

func IsVaulRecordChanged(statuses []v1alpha1.VaultRecordStatus, record *keyhubmodel.VaultRecord) bool {
	status := FindVaultRecordStatus(statuses, record.UUID)
	return status == nil || metav1.NewTime(record.LastModifiedAt()).Rfc3339Copy().After(status.LastModifiedAt.Time)
}

// SetSecretKeyStatus sets the corresponding status in statuses to newStatus.
// statuses must be non-nil.
func SetSecretKeyStatus(statuses *[]v1alpha1.SecretKeyStatus, key string, value []byte) error {
	if statuses == nil {
		statuses = &[]v1alpha1.SecretKeyStatus{}
		// return nil
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

func DeleteSecretKeyStatus(statuses []v1alpha1.SecretKeyStatus, keysToRemove map[string]struct{}) []v1alpha1.SecretKeyStatus {
	ret := make([]v1alpha1.SecretKeyStatus, 0)
	for _, status := range statuses {
		if _, found := keysToRemove[status.Key]; !found {
			ret = append(ret, status)
		}
	}
	return ret
}

// Compares current value of key against expected SecretKeyStatus
func IsSecretKeyChanged(statuses []v1alpha1.SecretKeyStatus, data map[string][]byte, key string) bool {
	encValue := make([]byte, base64.StdEncoding.EncodedLen(len(data[key])))
	base64.StdEncoding.Encode(encValue, data[key])

	status := FindSecretKeyStatus(statuses, key)

	return status == nil || bcrypt.CompareHashAndPassword(status.Hash, encValue) != nil
}
