// Copyright 2021 Topicus Security BV
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"time"

	"golang.org/x/crypto/bcrypt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	keyhubv1alpha1 "github.com/topicuskeyhub/keyhub-vault-operator/api/v1alpha1"
	controllerMetrics "github.com/topicuskeyhub/keyhub-vault-operator/controllers/metrics"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	controllers_test "github.com/topicuskeyhub/keyhub-vault-operator/controllers/test"
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

	Context("Opaque secret", func() {
		It("Should handle keys correctly", func() {
			spec := keyhubv1alpha1.KeyHubSecretSpec{
				Data: []keyhubv1alpha1.SecretKeyReference{
					{Name: "username", Record: "00000000-0000-0000-1001-000000000002", Property: "username"},
					{Name: "password", Record: "00000000-0000-0000-1001-000000000002", Property: "password"},
					{Name: "password_by_default", Record: "00000000-0000-0000-1001-000000000002"},
					{Name: "link", Record: "00000000-0000-0000-1001-000000000002", Property: "link"},
					{Name: "file", Record: "00000000-0000-0000-1001-000000000002", Property: "file"},
					{Name: "lastModifiedAt", Record: "00000000-0000-0000-1001-000000000002", Property: "lastModifiedAt"},
					{Name: "bcrypt", Record: "00000000-0000-0000-1001-000000000002", Property: "password", Format: "bcrypt"},
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
				manifestToLog = fetched

				validHash := bcrypt.CompareHashAndPassword(fetched.Data["bcrypt"], []byte("test1234"))

				return fetched.Type == corev1.SecretTypeOpaque &&
					len(fetched.Data) > 0 &&
					string(fetched.Data["username"]) == "admin" &&
					string(fetched.Data["password"]) == "test1234" &&
					string(fetched.Data["password_by_default"]) == "test1234" &&
					string(fetched.Data["link"]) == "http://example.com" &&
					string(fetched.Data["file"]) == "lorem ipsum" &&
					string(fetched.Data["lastModifiedAt"]) == "2020-01-01T16:00:30Z" &&
					validHash == nil
			}, timeout, interval).Should(BeTrue())
			manifestToLog = nil

			By("By checking the KeyHubSecret status")
			fetchedKeyHubSecret := &keyhubv1alpha1.KeyHubSecret{}
			Eventually(func() bool {
				k8sClient.Get(context.Background(), key, fetchedKeyHubSecret)
				manifestToLog = fetchedKeyHubSecret

				records := fetchedKeyHubSecret.Status.VaultRecordStatuses
				keys := fetchedKeyHubSecret.Status.SecretKeyStatuses

				return len(records) == 1 &&
					len(keys) == 7 &&
					records[0].RecordID == "00000000-0000-0000-1001-000000000002" &&
					records[0].Name == "Username + password"
			}, timeout, interval).Should(BeTrue())
			manifestToLog = nil

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

		It("Should handle KeyHubSecret updates correctly", func() {
			spec := keyhubv1alpha1.KeyHubSecretSpec{
				Data: []keyhubv1alpha1.SecretKeyReference{
					{Name: "username", Record: "00000000-0000-0000-1001-000000000002", Property: "username"},
					{Name: "pkey", Record: "00000000-0000-0000-1001-000000000004", Property: "username"},
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
				manifestToLog = fetched

				return fetched.Type == corev1.SecretTypeOpaque &&
					len(fetched.Data) == 2 &&
					string(fetched.Data["username"]) == "admin" &&
					string(fetched.Data["pkey"]) == "private.example.io"

			}, timeout, interval).Should(BeTrue())
			manifestToLog = nil

			By("By checking the KeyHubSecret status")
			fetchedKeyHubSecret := &keyhubv1alpha1.KeyHubSecret{}
			Eventually(func() bool {
				k8sClient.Get(context.Background(), key, fetchedKeyHubSecret)
				manifestToLog = fetchedKeyHubSecret

				records := fetchedKeyHubSecret.Status.VaultRecordStatuses
				keys := fetchedKeyHubSecret.Status.SecretKeyStatuses

				if len(records) != 2 && len(keys) != 2 {
					return false
				}

				return records[0].RecordID == "00000000-0000-0000-1001-000000000002" &&
					records[0].Name == "Username + password" &&
					records[1].RecordID == "00000000-0000-0000-1001-000000000004" &&
					records[1].Name == "Privatekey" &&
					keys[0].Key == "username" &&
					len(keys[0].Hash) > 0 &&
					keys[1].Key == "pkey" &&
					len(keys[1].Hash) > 0
			}, timeout, interval).Should(BeTrue())
			manifestToLog = nil

			By("Adding a key to the Secret")
			fetched.Data["custom"] = []byte("app_added_value")
			k8sClient.Update(context.Background(), fetched)

			By("By checking the Secret is updated correctly")
			fetched = &corev1.Secret{}
			Eventually(func() bool {
				k8sClient.Get(context.Background(), key, fetched)
				manifestToLog = fetched

				return fetched.Type == corev1.SecretTypeOpaque &&
					len(fetched.Data) == 3 &&
					string(fetched.Data["username"]) == "admin" &&
					string(fetched.Data["pkey"]) == "private.example.io" &&
					string(fetched.Data["custom"]) == "app_added_value"
			}, timeout, interval).Should(BeTrue())
			manifestToLog = nil

			By("By updating the KeyHubSecret")
			fetchedKeyHubSecret = &keyhubv1alpha1.KeyHubSecret{}
			k8sClient.Get(context.Background(), key, fetchedKeyHubSecret)
			fetchedKeyHubSecret.Spec.Data = []keyhubv1alpha1.SecretKeyReference{
				{Name: "username", Record: "00000000-0000-0000-1001-000000000003", Property: "username"},
				{Name: "cacerts", Record: "00000000-0000-0000-1001-000000000005", Property: "username"},
			}
			k8sClient.Update(context.Background(), fetchedKeyHubSecret)

			By("By checking the Secret is updated correctly")
			fetched = &corev1.Secret{}
			Eventually(func() bool {
				k8sClient.Get(context.Background(), key, fetched)
				manifestToLog = fetched

				return fetched.Type == corev1.SecretTypeOpaque &&
					len(fetched.Data) == 3 &&
					string(fetched.Data["username"]) == "example.io" &&
					string(fetched.Data["cacerts"]) == "ca_certs" &&
					string(fetched.Data["custom"]) == "app_added_value"
			}, timeout, interval).Should(BeTrue())
			manifestToLog = nil

			By("By checking the KeyHubSecret status is updated")
			fetchedKeyHubSecret = &keyhubv1alpha1.KeyHubSecret{}
			Eventually(func() bool {
				k8sClient.Get(context.Background(), key, fetchedKeyHubSecret)
				manifestToLog = fetchedKeyHubSecret

				records := fetchedKeyHubSecret.Status.VaultRecordStatuses
				keys := fetchedKeyHubSecret.Status.SecretKeyStatuses

				if len(records) != 2 && len(keys) != 2 {
					return false
				}

				return records[0].RecordID == "00000000-0000-0000-1001-000000000003" &&
					records[0].Name == "Certificate" &&
					records[1].RecordID == "00000000-0000-0000-1001-000000000005" &&
					records[1].Name == "CA Certs" &&
					keys[0].Key == "username" &&
					len(keys[0].Hash) > 0 &&
					keys[1].Key == "cacerts" &&
					len(keys[1].Hash) > 0
			}, timeout, interval).Should(BeTrue())
			manifestToLog = nil

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
