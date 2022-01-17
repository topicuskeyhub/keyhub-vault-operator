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
	"crypto/sha256"
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

	Context("TLS secret", func() {
		It("Should handle seperate records correctly", func() {
			spec := keyhubv1alpha1.KeyHubSecretSpec{
				Template: keyhubv1alpha1.SecretTemplate{
					Type: corev1.SecretTypeTLS,
				},
				Data: []keyhubv1alpha1.SecretKeyReference{
					{Name: "tls.crt", Record: "00000000-0000-0000-1001-000000000003"},
					{Name: "tls.key", Record: "00000000-0000-0000-1001-000000000004"},
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

				h := sha256.New()
				h.Write(fetched.Data[corev1.TLSCertKey])
				crtHash := fmt.Sprintf("%x", h.Sum(nil))
				h.Reset()
				h.Write(fetched.Data[corev1.TLSPrivateKeyKey])
				keyHash := fmt.Sprintf("%x", h.Sum(nil))

				return fetched.Type == corev1.SecretTypeTLS &&
					len(fetched.Data) == 2 &&
					fetched.Annotations["field.cattle.io/algorithm"] == "RSA" &&
					fetched.Annotations["field.cattle.io/certFingerprint"] == "B8:9B:18:E9:AF:EC:DA:E0:1A:2D:A7:F0:58:9E:A8:2A:88:56:41:90" &&
					fetched.Annotations["field.cattle.io/cn"] == "example.io" &&
					fetched.Annotations["field.cattle.io/expiresAt"] == "2031-03-24T07:19:37Z" &&
					fetched.Annotations["field.cattle.io/issuedAt"] == "2021-03-26T07:19:37Z" &&
					fetched.Annotations["field.cattle.io/issuer"] == "example.io" &&
					fetched.Annotations["field.cattle.io/serialNumber"] == "16527872211062900695" &&
					fetched.Annotations["field.cattle.io/version"] == "3" &&
					fetched.Annotations["field.cattle.io/keySize"] == "2048" &&
					fetched.Annotations["field.cattle.io/subjectAlternativeNames"] == "[\"example.io\"]" &&
					crtHash == "92af8e97f4ef72af245e6d805468a30556cf5bcc52a40a5301fd78b55515f172" &&
					keyHash == "9f76ad4473255e2220c0bbb64a20f1ceec58565ff2f17728fe7bb2f057fe8dcb"

			}, timeout, interval).Should(BeTrue())

			By("By checking the KeyHubSecret status")
			fetchedKeyHubSecret := &keyhubv1alpha1.KeyHubSecret{}
			Eventually(func() bool {
				k8sClient.Get(context.Background(), key, fetchedKeyHubSecret)
				manifestToLog = fetchedKeyHubSecret

				records := fetchedKeyHubSecret.Status.VaultRecordStatuses
				keys := fetchedKeyHubSecret.Status.SecretKeyStatuses

				return len(records) == 2 &&
					len(keys) == 2 &&
					records[0].RecordID == "00000000-0000-0000-1001-000000000004" &&
					records[0].Name == "Privatekey" &&
					records[1].RecordID == "00000000-0000-0000-1001-000000000003" &&
					records[1].Name == "Certificate" &&
					keys[0].Key == corev1.TLSCertKey &&
					keys[1].Key == corev1.TLSPrivateKeyKey
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

	It("Should handle seperate records with ca certs correctly", func() {
		spec := keyhubv1alpha1.KeyHubSecretSpec{
			Template: keyhubv1alpha1.SecretTemplate{
				Type: corev1.SecretTypeTLS,
			},
			Data: []keyhubv1alpha1.SecretKeyReference{
				{Name: "tls.crt", Record: "00000000-0000-0000-1001-000000000003"},
				{Name: "tls.key", Record: "00000000-0000-0000-1001-000000000004"},
				{Name: "ca.crt", Record: "00000000-0000-0000-1001-000000000005"},
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

			h := sha256.New()
			h.Write(fetched.Data[corev1.TLSCertKey])
			crtHash := fmt.Sprintf("%x", h.Sum(nil))
			h.Reset()
			h.Write(fetched.Data[corev1.TLSPrivateKeyKey])
			keyHash := fmt.Sprintf("%x", h.Sum(nil))

			return fetched.Type == corev1.SecretTypeTLS &&
				len(fetched.Data) == 2 &&
				crtHash == "7827b5dc11728f92186350064bf28208a503dc0c4f14806d33eae1a659b0dee0" &&
				keyHash == "9f76ad4473255e2220c0bbb64a20f1ceec58565ff2f17728fe7bb2f057fe8dcb"
		}, timeout, interval).Should(BeTrue())

		By("By checking the KeyHubSecret status")
		fetchedKeyHubSecret := &keyhubv1alpha1.KeyHubSecret{}
		Eventually(func() bool {
			k8sClient.Get(context.Background(), key, fetchedKeyHubSecret)
			manifestToLog = fetchedKeyHubSecret

			records := fetchedKeyHubSecret.Status.VaultRecordStatuses
			keys := fetchedKeyHubSecret.Status.SecretKeyStatuses

			return len(records) == 3 &&
				len(keys) == 2 &&
				records[0].RecordID == "00000000-0000-0000-1001-000000000004" &&
				records[0].Name == "Privatekey" &&
				records[1].RecordID == "00000000-0000-0000-1001-000000000003" &&
				records[1].Name == "Certificate" &&
				records[2].RecordID == "00000000-0000-0000-1001-000000000005" &&
				records[2].Name == "CA Certs" &&
				keys[0].Key == corev1.TLSCertKey &&
				keys[1].Key == corev1.TLSPrivateKeyKey
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

	It("Should handle pem correctly", func() {
		spec := keyhubv1alpha1.KeyHubSecretSpec{
			Template: keyhubv1alpha1.SecretTemplate{
				Type: corev1.SecretTypeTLS,
			},
			Data: []keyhubv1alpha1.SecretKeyReference{
				{Name: "pem", Record: "00000000-0000-0000-1001-000000000006"},
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

			h := sha256.New()
			h.Write(fetched.Data[corev1.TLSCertKey])
			crtHash := fmt.Sprintf("%x", h.Sum(nil))
			h.Reset()
			h.Write(fetched.Data[corev1.TLSPrivateKeyKey])
			keyHash := fmt.Sprintf("%x", h.Sum(nil))

			return fetched.Type == corev1.SecretTypeTLS &&
				len(fetched.Data) == 2 &&
				crtHash == "92af8e97f4ef72af245e6d805468a30556cf5bcc52a40a5301fd78b55515f172" &&
				keyHash == "9f76ad4473255e2220c0bbb64a20f1ceec58565ff2f17728fe7bb2f057fe8dcb"
		}, timeout, interval).Should(BeTrue())

		By("By checking the KeyHubSecret status")
		fetchedKeyHubSecret := &keyhubv1alpha1.KeyHubSecret{}
		Eventually(func() bool {
			k8sClient.Get(context.Background(), key, fetchedKeyHubSecret)
			manifestToLog = fetchedKeyHubSecret

			records := fetchedKeyHubSecret.Status.VaultRecordStatuses
			keys := fetchedKeyHubSecret.Status.SecretKeyStatuses

			return len(records) == 1 &&
				len(keys) == 2 &&
				records[0].RecordID == "00000000-0000-0000-1001-000000000006" &&
				records[0].Name == "PEM" &&
				keys[0].Key == corev1.TLSCertKey &&
				keys[1].Key == corev1.TLSPrivateKeyKey
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

	It("Should handle pem including a chain correctly", func() {
		spec := keyhubv1alpha1.KeyHubSecretSpec{
			Template: keyhubv1alpha1.SecretTemplate{
				Type: corev1.SecretTypeTLS,
			},
			Data: []keyhubv1alpha1.SecretKeyReference{
				{Name: "pem", Record: "00000000-0000-0000-1001-000000000007"},
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

			h := sha256.New()
			h.Write(fetched.Data[corev1.TLSCertKey])
			crtHash := fmt.Sprintf("%x", h.Sum(nil))
			h.Reset()
			h.Write(fetched.Data[corev1.TLSPrivateKeyKey])
			keyHash := fmt.Sprintf("%x", h.Sum(nil))

			return fetched.Type == corev1.SecretTypeTLS &&
				len(fetched.Data) == 2 &&
				crtHash == "7827b5dc11728f92186350064bf28208a503dc0c4f14806d33eae1a659b0dee0" &&
				keyHash == "9f76ad4473255e2220c0bbb64a20f1ceec58565ff2f17728fe7bb2f057fe8dcb"
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
				len(keys) == 2 &&
				records[0].RecordID == "00000000-0000-0000-1001-000000000007" &&
				records[0].Name == "PEM WITH CHAIN" &&
				keys[0].Key == corev1.TLSCertKey &&
				keys[1].Key == corev1.TLSPrivateKeyKey
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

	It("Should handle pkcs12 correctly", func() {
		spec := keyhubv1alpha1.KeyHubSecretSpec{
			Template: keyhubv1alpha1.SecretTemplate{
				Type: corev1.SecretTypeTLS,
			},
			Data: []keyhubv1alpha1.SecretKeyReference{
				{Name: "pkcs12", Record: "00000000-0000-0000-1001-000000000009"},
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

			h := sha256.New()
			h.Write(fetched.Data[corev1.TLSCertKey])
			crtHash := fmt.Sprintf("%x", h.Sum(nil))
			h.Reset()
			h.Write(fetched.Data[corev1.TLSPrivateKeyKey])
			keyHash := fmt.Sprintf("%x", h.Sum(nil))

			return fetched.Type == corev1.SecretTypeTLS &&
				len(fetched.Data) == 2 &&
				crtHash == "9fdb3c05d7153487ab85efb5630acfaf528c456cf823fcc5fd04a79e7d6ed12e" &&
				keyHash == "1cee0f3daa68714795d98cacb98e68b65a27f4701cc0196727dba59ea582bf98"
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
				len(keys) == 2 &&
				records[0].RecordID == "00000000-0000-0000-1001-000000000009" &&
				records[0].Name == "PKCS#12 without CA chain" &&
				keys[0].Key == corev1.TLSCertKey &&
				keys[1].Key == corev1.TLSPrivateKeyKey
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

	It("Should handle pkcs12 with ca certs correctly", func() {
		spec := keyhubv1alpha1.KeyHubSecretSpec{
			Template: keyhubv1alpha1.SecretTemplate{
				Type: corev1.SecretTypeTLS,
			},
			Data: []keyhubv1alpha1.SecretKeyReference{
				{Name: "pkcs12", Record: "00000000-0000-0000-1001-000000000010"},
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

			h := sha256.New()
			h.Write(fetched.Data[corev1.TLSCertKey])
			crtHash := fmt.Sprintf("%x", h.Sum(nil))
			h.Reset()
			h.Write(fetched.Data[corev1.TLSPrivateKeyKey])
			keyHash := fmt.Sprintf("%x", h.Sum(nil))

			return fetched.Type == corev1.SecretTypeTLS &&
				len(fetched.Data) == 2 &&
				crtHash == "f9fd4f2ffbeb19bf2c59bdaa257915e8f8af03d3f4c9ce1700ef45dc96139784" &&
				keyHash == "1cee0f3daa68714795d98cacb98e68b65a27f4701cc0196727dba59ea582bf98"
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
				len(keys) == 2 &&
				records[0].RecordID == "00000000-0000-0000-1001-000000000010" &&
				records[0].Name == "PKCS#12 with CA chain" &&
				keys[0].Key == corev1.TLSCertKey &&
				keys[1].Key == corev1.TLSPrivateKeyKey
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
