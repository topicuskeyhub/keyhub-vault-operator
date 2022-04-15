// Copyright 2020 Topicus Security BV
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	keyhubv1alpha1 "github.com/topicusonderwijs/keyhub-vault-operator/api/v1alpha1"
	"github.com/topicusonderwijs/keyhub-vault-operator/controllers/policy"
	controllers_test "github.com/topicusonderwijs/keyhub-vault-operator/controllers/test"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var _ = Describe("Namespace Policy Resolver", func() {

	const timeout = time.Second * 10
	const interval = time.Second * 1

	BeforeEach(func() {
		// Failed test runs that don't clean up leave resources behind.
		cfg := controllers_test.BeforeEachInputs{Client: k8sClient}
		controllers_test.CleanUp(&cfg)

		ns := &corev1.NamespaceList{}
		k8sClient.List(context.Background(), ns)
		for _, obj := range ns.Items {
			if strings.HasPrefix(obj.Name, "resolver1-test-") {
				fmt.Println("removing namespace", "name", obj.Name)
				Eventually(func() error {
					return k8sClient.Delete(context.Background(), &obj)
				}, timeout, interval).Should(Succeed())
				// Stuck in deleting > 30 secs
				// Eventually(func() error {
				// 	return k8sClient.Get(
				// 		context.Background(),
				// 		types.NamespacedName{Name: obj.Name},
				// 		&corev1.Namespace{},
				// 	)
				// }, timeout*3, interval).ShouldNot(BeNil())
			}
		}
	})

	Context("No policy match", func() {
		It("Should not find a policy match", func() {
			ks := &keyhubv1alpha1.KeyHubSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sample-ks",
					Namespace: "default",
				},
				Spec: keyhubv1alpha1.KeyHubSecretSpec{
					Data: []keyhubv1alpha1.SecretKeyReference{
						{Name: "username", Record: "1001-0002", Property: "username"},
					},
				},
			}

			p := policy.Policy{}
			p.Type = "unknown"
			p.Name = "default"
			p.Credentials = policy.ClientCredentials{ClientID: "1357"}
			policies := []policy.Policy{p}

			resolver := policy.NewNamespacePolicyResolver(k8sClient, logf.Log.WithName("NamespacePolicyResolver"), policies)
			policy, err := resolver.Resolve(ks)
			Expect(err).ToNot(BeNil())
			Expect(err.Error()).To(Equal("No credentials found for namespace default"))
			Expect(policy).To(BeNil())
		})
	})

	Context("Name Match", func() {
		It("Should match the policy by namespace", func() {
			ks := &keyhubv1alpha1.KeyHubSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sample-ks",
					Namespace: "default",
				},
				Spec: keyhubv1alpha1.KeyHubSecretSpec{
					Data: []keyhubv1alpha1.SecretKeyReference{
						{Name: "username", Record: "1001-0002", Property: "username"},
					},
				},
			}

			p := policy.Policy{}
			p.Type = "namespace"
			p.Name = "default"
			p.Credentials = policy.ClientCredentials{ClientID: "1357"}
			policies := []policy.Policy{p}

			resolver := policy.NewNamespacePolicyResolver(k8sClient, logf.Log.WithName("NamespacePolicyResolver"), policies)
			policy, err := resolver.Resolve(ks)
			Expect(err).To(BeNil())
			Expect(policy).ToNot(BeNil())
			Expect(policy.Credentials.ClientID).To(Equal("1357"))
		})
	})

	Context("LabelSelector Match", func() {
		It("Should find a namespace match", func() {
			By("By creating a labeled namespace")
			nsl := &corev1.NamespaceList{
				Items: []corev1.Namespace{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "resolver-test-1-1",
							Labels: map[string]string{
								"project": "x",
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "resolver-test-1-2",
							Labels: map[string]string{
								"project": "y",
							},
						},
					},
				},
			}
			for _, ns := range nsl.Items {
				Eventually(func() error {
					return k8sClient.Create(context.Background(), &ns)
				}, timeout, interval).Should(Succeed())
			}

			By("By resolving the policy for a KeyHubSecret in a labeled namespace")
			ks := &keyhubv1alpha1.KeyHubSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sample-ks",
					Namespace: "resolver-test-1-1",
				},
				Spec: keyhubv1alpha1.KeyHubSecretSpec{
					Data: []keyhubv1alpha1.SecretKeyReference{
						{Name: "username", Record: "1001-0002", Property: "username"},
					},
				},
			}

			p1 := policy.Policy{}
			p1.Type = "namespace"
			p1.LabelSelector = "project=x"
			p1.Credentials = policy.ClientCredentials{ClientID: "1357"}
			p2 := policy.Policy{}
			p2.Type = "namespace"
			p2.LabelSelector = "project=y"
			p2.Credentials = policy.ClientCredentials{ClientID: "0246"}
			policies := []policy.Policy{p1, p2}

			resolver := policy.NewNamespacePolicyResolver(k8sClient, logf.Log.WithName("NamespacePolicyResolver"), policies)
			policy, err := resolver.Resolve(ks)
			Expect(err).To(BeNil())
			Expect(policy).ToNot(BeNil())
			Expect(policy.Credentials.ClientID).To(Equal("1357"))
		})

		It("Should find the most specific namespace match", func() {
			By("By creating multiple labeled namespaces")
			nsl := &corev1.NamespaceList{
				Items: []corev1.Namespace{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "resolver-test-2-1",
							Labels: map[string]string{
								"project":   "x",
								"component": "1",
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "resolver-test-2-2",
							Labels: map[string]string{
								"project": "x",
							},
						},
					},
				},
			}
			for _, ns := range nsl.Items {
				Expect(k8sClient.Create(context.Background(), &ns)).To(BeNil())
			}

			By("By resolving the policy for a KeyHubSecret in a labeled namespace")
			ks := &keyhubv1alpha1.KeyHubSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sample-ks",
					Namespace: "resolver-test-2-1",
				},
				Spec: keyhubv1alpha1.KeyHubSecretSpec{
					Data: []keyhubv1alpha1.SecretKeyReference{
						{Name: "username", Record: "1001-0002", Property: "username"},
					},
				},
			}

			p1 := policy.Policy{}
			p1.Type = "namespace"
			p1.LabelSelector = "project=x"
			p1.Credentials = policy.ClientCredentials{ClientID: "1357"}
			p2 := policy.Policy{}
			p2.Type = "namespace"
			p2.LabelSelector = "component=1"
			p2.Credentials = policy.ClientCredentials{ClientID: "0246"}
			policies := []policy.Policy{p1, p2}

			resolver := policy.NewNamespacePolicyResolver(k8sClient, logf.Log.WithName("NamespacePolicyResolver"), policies)
			policy, err := resolver.Resolve(ks)
			Expect(err).To(BeNil())
			Expect(policy).ToNot(BeNil())
			Expect(policy.Credentials.ClientID).To(Equal("0246"))
		})

		It("Should fail when two policies have the same score", func() {
			By("By creating multiple labeled namespaces")
			nsl := &corev1.NamespaceList{
				Items: []corev1.Namespace{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "resolver-test-3-1",
							Labels: map[string]string{
								"project": "x3",
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "resolver-test-3-2",
							Labels: map[string]string{
								"project": "x3",
							},
						},
					},
				},
			}
			for _, ns := range nsl.Items {
				Expect(k8sClient.Create(context.Background(), &ns)).To(BeNil())
			}

			// Wait for namespaces to be available
			fetched := &corev1.Namespace{}
			for _, ns := range nsl.Items {
				key := types.NamespacedName{
					Name: ns.Name,
				}
				Eventually(func() bool {
					k8sClient.Get(context.Background(), key, fetched)
					return len(fetched.Labels) == 1
				}, timeout, interval).Should(BeTrue())

			}

			By("By resolving the policy for a KeyHubSecret in a labeled namespace")
			ks := &keyhubv1alpha1.KeyHubSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sample-ks",
					Namespace: "resolver-test-3-1",
				},
				Spec: keyhubv1alpha1.KeyHubSecretSpec{
					Data: []keyhubv1alpha1.SecretKeyReference{
						{Name: "username", Record: "1001-0002", Property: "username"},
					},
				},
			}

			p1 := policy.Policy{}
			p1.Type = "namespace"
			p1.LabelSelector = "project=x3"
			p1.Credentials = policy.ClientCredentials{ClientID: "1357"}
			p2 := policy.Policy{}
			p2.Type = "namespace"
			p2.LabelSelector = "project=x3"
			p2.Credentials = policy.ClientCredentials{ClientID: "0246"}
			policies := []policy.Policy{p1, p2}

			resolver := policy.NewNamespacePolicyResolver(k8sClient, logf.Log.WithName("NamespacePolicyResolver"), policies)
			policy, err := resolver.Resolve(ks)
			Expect(err).ToNot(BeNil())
			Expect(policy).To(BeNil())
		})

	})
})
