// Copyright 2021 Topicus Security BV
// SPDX-License-Identifier: Apache-2.0

package controllers_test

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	keyhubv1alpha1 "github.com/topicusonderwijs/keyhub-vault-operator/api/v1alpha1"
)

type BeforeEachInputs struct {
	Client client.Client
}

func CleanUp(inputs *BeforeEachInputs) {
	ks := &keyhubv1alpha1.KeyHubSecretList{}
	inputs.Client.List(context.Background(), ks)
	for _, obj := range ks.Items {
		inputs.Client.Delete(context.Background(), &obj)
	}
	s := &corev1.SecretList{}
	inputs.Client.List(context.Background(), s)
	for _, obj := range s.Items {
		if obj.Name != "keyhub-vault-operator-secret" {
			inputs.Client.Delete(context.Background(), &obj)
		}
	}
}
