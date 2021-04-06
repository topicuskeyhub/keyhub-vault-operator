/*
Copyright 2020.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// KeyHubSecretSpec defines the desired state of KeyHubSecret
// +kubebuilder:validation:XPreserveUnknownFields
type KeyHubSecretSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +optional
	Template SecretTemplate `json:"template,omitempty"`

	Data []SecretKeyReference `json:"data"`
}

type SecretTemplate struct {
	// +optional
	Type corev1.SecretType `json:"type,omitempty"`

	// +optional
	Metadata SecretTemplateMetadata `json:"metadata,omitempty"`
}

type SecretTemplateMetadata struct {
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// SecretKeyReference defines the mapping between a KeyHub vault record and a K8s Secret key
type SecretKeyReference struct {
	Name string `json:"name"`

	Record string `json:"record"`

	// +kubebuilder:default:="password"
	Property string `json:"property,omitempty"`

	// +optional
	Format string `json:"format,omitempty"`
}

type KeyHubSecretConditionType string

var (
	TypeSynced KeyHubSecretConditionType = "Synced"
)

type KeyHubSecretConditionReason string

var (
	AwaitingSync KeyHubSecretConditionReason = "AwaitingSync"
)

type VaultRecordStatus struct {
	RecordID string `json:"recordID"`

	Name string `json:"name"`

	// +optional
	// LastModifiedAt is the timestamp this record was last modified in KeyHub
	// +optional
	LastModifiedAt metav1.Time `json:"lastModifiedAt,omitempty"`
}

type SecretKeyStatus struct {
	Key string `json:"key"`

	Hash []byte `json:"hash"`
}

// KeyHubSecretStatus defines the observed state of KeyHubSecret
type KeyHubSecretStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	ObservedSecretGeneration int64 `json:"observedGeneration,omitempty"`

	// +optional
	VaultRecordStatuses []VaultRecordStatus `json:"vaultRecordStatuses,omitempty"`

	// +optional
	SecretKeyStatuses []SecretKeyStatus `json:"secretKeyStatuses,omitempty"`
}

type VaultRecordState2 struct {
	Record string `json:"record"`

	Name string `json:"name"`

	// LastModifiedAt is the timestamp this record was last modified in KeyHub
	// +optional
	LastModifiedAt *metav1.Time `json:"lastModifiedAt,omitempty"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	// LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +optional
	// Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// KeyHubSecret is the Schema for the keyhubsecrets API
type KeyHubSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeyHubSecretSpec   `json:"spec,omitempty"`
	Status KeyHubSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeyHubSecretList contains a list of KeyHubSecret
type KeyHubSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeyHubSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeyHubSecret{}, &KeyHubSecretList{})
}
