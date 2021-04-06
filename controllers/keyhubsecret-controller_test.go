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

	"golang.org/x/crypto/bcrypt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	keyhubv1alpha1 "github.com/topicusonderwijs/keyhub-vault-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("KeyHubSecret Controller", func() {

	const timeout = time.Second * 10
	const interval = time.Second * 1

	BeforeEach(func() {
		// failed test runs that don't clean up leave resources behind.
		ks := &keyhubv1alpha1.KeyHubSecretList{}
		k8sClient.List(context.Background(), ks)
		for _, obj := range ks.Items {
			k8sClient.Delete(context.Background(), &obj)
		}
		s := &corev1.SecretList{}
		k8sClient.List(context.Background(), s)
		for _, obj := range s.Items {
			if obj.Name != "keyhub-secrets-controller-secret" {
				k8sClient.Delete(context.Background(), &obj)
			}
		}
	})

	AfterEach(func() {
		// Add any teardown steps that needs to be executed after each test
	})

	Context("Labels and annotations", func() {
		It("Should handle default labels correctly", func() {
			spec := keyhubv1alpha1.KeyHubSecretSpec{
				Data: []keyhubv1alpha1.SecretKeyReference{
					{Name: "username", Record: "1001-0002", Property: "username"},
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
				fmt.Println(fetched)
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
					{Name: "username", Record: "1001-0002", Property: "username"},
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
					{Name: "username", Record: "1001-0002", Property: "username"},
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

	Context("Opaque secret", func() {
		It("Should handle keys correctly", func() {
			spec := keyhubv1alpha1.KeyHubSecretSpec{
				Data: []keyhubv1alpha1.SecretKeyReference{
					{Name: "username", Record: "1001-0002", Property: "username"},
					{Name: "password", Record: "1001-0002", Property: "password"},
					{Name: "password_by_default", Record: "1001-0002"},
					{Name: "link", Record: "1001-0002", Property: "link"},
					{Name: "file", Record: "1001-0002", Property: "file"},
					{Name: "lastModifiedAt", Record: "1001-0002", Property: "lastModifiedAt"},
					{Name: "bcrypt", Record: "1001-0002", Property: "password", Format: "bcrypt"},
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

	Context("BasicAuth secret", func() {
		It("Should handle basic auth credentials correctly", func() {
			spec := keyhubv1alpha1.KeyHubSecretSpec{
				Template: keyhubv1alpha1.SecretTemplate{
					Type: corev1.SecretTypeBasicAuth,
				},
				Data: []keyhubv1alpha1.SecretKeyReference{
					{Name: "auth", Record: "1001-0002"},
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
				return fetched.Type == corev1.SecretTypeBasicAuth &&
					len(fetched.Data) > 0 &&
					string(fetched.Data["username"]) == "admin" &&
					string(fetched.Data["password"]) == "test1234"
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

	Context("SSHAuth secret", func() {
		It("Should handle ssh auth correctly", func() {
			spec := keyhubv1alpha1.KeyHubSecretSpec{
				Template: keyhubv1alpha1.SecretTemplate{
					Type: corev1.SecretTypeSSHAuth,
				},
				Data: []keyhubv1alpha1.SecretKeyReference{
					{Name: "key", Record: "1001-0002"},
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
				return fetched.Type == corev1.SecretTypeSSHAuth &&
					len(fetched.Data) == 1 &&
					string(fetched.Data[corev1.SSHAuthPrivateKey]) == "lorem ipsum"
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

	Context("TLS secret", func() {
		It("Should handle seperate records correctly", func() {
			spec := keyhubv1alpha1.KeyHubSecretSpec{
				Template: keyhubv1alpha1.SecretTemplate{
					Type: corev1.SecretTypeTLS,
				},
				Data: []keyhubv1alpha1.SecretKeyReference{
					{Name: "tls.crt", Record: "1001-0003"},
					{Name: "tls.key", Record: "1001-0004"},
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
				{Name: "tls.crt", Record: "1001-0003"},
				{Name: "tls.key", Record: "1001-0004"},
				{Name: "ca.crt", Record: "1001-0005"},
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
				{Name: "pem", Record: "1001-0006"},
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
				{Name: "pem", Record: "1001-0007"},
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

			fmt.Println(fetched)
			fmt.Println("cert with chain", fetched.Data[corev1.TLSCertKey])
			fmt.Println("crt hash", crtHash)

			return fetched.Type == corev1.SecretTypeTLS &&
				len(fetched.Data) == 2 &&
				crtHash == "7827b5dc11728f92186350064bf28208a503dc0c4f14806d33eae1a659b0dee0" &&
				keyHash == "9f76ad4473255e2220c0bbb64a20f1ceec58565ff2f17728fe7bb2f057fe8dcb"
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

	It("Should handle pkcs12 correctly", func() {

	})

	It("Should handle pkcs12 with ca certs correctly", func() {

	})

})
