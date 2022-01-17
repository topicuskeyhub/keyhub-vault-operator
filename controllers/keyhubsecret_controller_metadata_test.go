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

package controllers

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	keyhubv1alpha1 "github.com/topicusonderwijs/keyhub-vault-operator/api/v1alpha1"
	controllerMetrics "github.com/topicusonderwijs/keyhub-vault-operator/controllers/metrics"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	controllers_test "github.com/topicusonderwijs/keyhub-vault-operator/controllers/test"
)

var _ = Describe("KeyHubSecret Controller", func() {

	const timeout = time.Second * 10
	const interval = time.Second * 1

	var manifestToLog interface{}

	BeforeEach(func() {
		manifestToLog = nil

		// Flush caches
		policyEngine.Flush()
		vaultIndexCache.Flush()

		// Failed test runs that don't clean up leave resources behind.
		cfg := controllers_test.BeforeEachInputs{Client: k8sClient}
		controllers_test.CleanUp(&cfg)

		// Reset Prometheus collectors
		controllerMetrics.Reset()
	})

	AfterEach(func() {
		// Add any teardown steps that needs to be executed after each test
		controllers_test.LogManifest(manifestToLog)
	})

	Context("Labels and annotations", func() {
		It("Should handle default labels correctly", func() {
			spec := keyhubv1alpha1.KeyHubSecretSpec{
				Data: []keyhubv1alpha1.SecretKeyReference{
					{Name: "username", Record: "00000000-0000-0000-1001-000000000002", Property: "username"},
				},
			}

			key := types.NamespacedName{
				Name:      "sample-ks",
				Namespace: "default",
			}

			toCreate := &keyhubv1alpha1.KeyHubSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sample-ks",
					Namespace: "default",
					Labels: map[string]string{
						"app.kubernetes.io/name":       "name",
						"helm.sh/chart":                "chart",
						"app.kubernetes.io/managed-by": "managed-by",
						"app.kubernetes.io/instance":   "instance",
						"app.kubernetes.io/version":    "version",
						"app.kubernetes.io/component":  "component",
						"app.kubernetes.io/part-of":    "part-of",
					},
				},
				Spec: spec,
			}

			By("By creating a new KeyHubSecret")
			Expect(k8sClient.Create(context.Background(), toCreate)).Should(Succeed())

			By("By checking the Secret is created correctly")
			fetched := &corev1.Secret{}
			Eventually(func() bool {
				k8sClient.Get(context.Background(), key, fetched)
				return fetched.Type == corev1.SecretTypeOpaque &&
					fetched.Labels["app.kubernetes.io/name"] == "name" &&
					fetched.Labels["helm.sh/chart"] == "chart" &&
					fetched.Labels["app.kubernetes.io/managed-by"] == "managed-by" &&
					fetched.Labels["app.kubernetes.io/instance"] == "instance" &&
					fetched.Labels["app.kubernetes.io/version"] == "version" &&
					fetched.Labels["app.kubernetes.io/component"] == "component" &&
					fetched.Labels["app.kubernetes.io/part-of"] == "part-of"
			}, timeout, interval).Should(BeTrue())

			By("Deleting the KeyHubSecret and Secret")
			Eventually(func() error {
				f := &keyhubv1alpha1.KeyHubSecret{}
				k8sClient.Get(context.Background(), key, f)
				return k8sClient.Delete(context.Background(), f)
			}, timeout, interval).Should(Succeed())
			Eventually(func() error {
				f := &corev1.Secret{}
				k8sClient.Get(context.Background(), key, f)
				return k8sClient.Delete(context.Background(), f)
			}, timeout, interval).Should(Succeed())
		})

		It("Should handle custom labels correctly", func() {
			spec := keyhubv1alpha1.KeyHubSecretSpec{
				Template: keyhubv1alpha1.SecretTemplate{
					Metadata: keyhubv1alpha1.SecretTemplateMetadata{
						Labels: map[string]string{
							"custom-label": "custom-value",
						},
					},
				},
				Data: []keyhubv1alpha1.SecretKeyReference{
					{Name: "username", Record: "00000000-0000-0000-1001-000000000002", Property: "username"},
				},
			}

			key := types.NamespacedName{
				Name:      "sample-ks",
				Namespace: "default",
			}

			toCreate := &keyhubv1alpha1.KeyHubSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sample-ks",
					Namespace: "default",
				},
				Spec: spec,
			}

			By("By creating a new KeyHubSecret")
			Expect(k8sClient.Create(context.Background(), toCreate)).Should(Succeed())

			By("By checking the Secret is created correctly")
			fetched := &corev1.Secret{}
			Eventually(func() bool {
				k8sClient.Get(context.Background(), key, fetched)
				return fetched.Type == corev1.SecretTypeOpaque &&
					fetched.Labels["custom-label"] == "custom-value"
			}, timeout, interval).Should(BeTrue())

			By("Deleting the KeyHubSecret and Secret")
			Eventually(func() error {
				f := &keyhubv1alpha1.KeyHubSecret{}
				k8sClient.Get(context.Background(), key, f)
				return k8sClient.Delete(context.Background(), f)
			}, timeout, interval).Should(Succeed())
			Eventually(func() error {
				f := &corev1.Secret{}
				k8sClient.Get(context.Background(), key, f)
				return k8sClient.Delete(context.Background(), f)
			}, timeout, interval).Should(Succeed())
		})

		It("Should handle annotations correctly", func() {
			spec := keyhubv1alpha1.KeyHubSecretSpec{
				Template: keyhubv1alpha1.SecretTemplate{
					Metadata: keyhubv1alpha1.SecretTemplateMetadata{
						Annotations: map[string]string{
							"custom-annotation": "custom-value",
						},
					},
				},
				Data: []keyhubv1alpha1.SecretKeyReference{
					{Name: "username", Record: "00000000-0000-0000-1001-000000000002", Property: "username"},
				},
			}

			key := types.NamespacedName{
				Name:      "sample-ks",
				Namespace: "default",
			}

			toCreate := &keyhubv1alpha1.KeyHubSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sample-ks",
					Namespace: "default",
				},
				Spec: spec,
			}

			By("By creating a new KeyHubSecret")
			Expect(k8sClient.Create(context.Background(), toCreate)).Should(Succeed())

			By("By checking the Secret is created correctly")
			fetched := &corev1.Secret{}
			Eventually(func() bool {
				k8sClient.Get(context.Background(), key, fetched)
				fmt.Println(fetched)
				return fetched.Type == corev1.SecretTypeOpaque &&
					fetched.Annotations["custom-annotation"] == "custom-value"
			}, timeout, interval).Should(BeTrue())

			By("Deleting the KeyHubSecret and Secret")
			Eventually(func() error {
				f := &keyhubv1alpha1.KeyHubSecret{}
				k8sClient.Get(context.Background(), key, f)
				return k8sClient.Delete(context.Background(), f)
			}, timeout, interval).Should(Succeed())
			Eventually(func() error {
				f := &corev1.Secret{}
				k8sClient.Get(context.Background(), key, f)
				return k8sClient.Delete(context.Background(), f)
			}, timeout, interval).Should(Succeed())
		})
	})
})
