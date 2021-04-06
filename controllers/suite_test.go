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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	ctrl "sigs.k8s.io/controller-runtime"

	keyhubv1alpha1 "github.com/topicusonderwijs/keyhub-vault-operator/api/v1alpha1"
	"github.com/topicusonderwijs/keyhub-vault-operator/controllers/policy"
	"github.com/topicusonderwijs/keyhub-vault-operator/controllers/settings"
	"github.com/topicusonderwijs/keyhub-vault-operator/controllers/vault"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func(done Done) {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "config", "crd", "bases")},
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = keyhubv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	Expect(err).ToNot(HaveOccurred())

	settingsMgr := settings.CreateSettingsManager(
		k8sManager.GetClient(),
		ctrl.Log.WithName("SettingsManager"),
	)

	policyEngine := policy.NewPolicyEngine(
		k8sManager.GetClient(),
		ctrl.Log.WithName("PolicyEngine"),
		settingsMgr,
	)

	vaultIndexCache := vault.NewVaultIndexCache(
		ctrl.Log.WithName("VaultIndexCache"),
	)

	err = (&KeyHubSecretReconciler{
		Client:          k8sManager.GetClient(),
		Log:             ctrl.Log.WithName("controllers").WithName("KeyHubSecret"),
		Scheme:          k8sManager.GetScheme(),
		Recorder:        k8sManager.GetEventRecorderFor("KeyHubSecret"),
		SettingsManager: settingsMgr,
		PolicyEngine:    policyEngine,
		VaultIndexCache: vaultIndexCache,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		err = k8sManager.Start(ctrl.SetupSignalHandler())
		Expect(err).ToNot(HaveOccurred())
	}()

	k8sClient = k8sManager.GetClient()
	Expect(k8sClient).ToNot(BeNil())

	ts := newKeyHubMockServer()

	toCreate := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "keyhub-secrets-controller-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"uri":          []byte(ts.URL),
			"clientId":     []byte("CONTROLLER"),
			"clientSecret": []byte("VERY_SECRET_PHRASE"),
		},
	}

	Expect(k8sClient.Create(context.Background(), toCreate)).Should(Succeed())

	close(done)
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

func newKeyHubMockServer() *httptest.Server {
	rtr := mux.NewRouter()

	rtr.HandleFunc("/.well-known/openid-configuration", routeOpenIDConfig)
	rtr.HandleFunc("/login/oauth2/token", routeOAuth2Token)

	v1 := rtr.PathPrefix("/keyhub/rest/v1").Subrouter()

	v1.HandleFunc("/info", routeInfo)

	v1.HandleFunc("/group", routeGroups)
	v1.HandleFunc("/group/{id:[0-9]+}/vault/record", routeVaultRecord).Queries("additional", "{additional}", "uuid", "{group:[\\w]+}-{uuid:[\\w]+}")
	v1.HandleFunc("/group/{id:[0-9]+}/vault/record", routeVaultRecords).Queries("additional", "audit")

	rtr.Use(onRequestBegin)

	return httptest.NewServer(rtr)
}

func onRequestBegin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		fmt.Println("Begin request", "method", r.Method, "path", r.URL.Path, "params", vars)
		next.ServeHTTP(w, r)
	})
}

func routeDefault(w http.ResponseWriter, r *http.Request) {
	fmt.Println("No route found", r.URL.Path)
	w.WriteHeader(http.StatusNotFound)
}

func routeInfo(w http.ResponseWriter, r *http.Request) {
	writeJSONResponse(w, "../testdata/info.json")
}

func routeOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadFile("../testdata/openid-configuration.json")
	if err != nil {
		fmt.Println("File reading error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	modded := strings.ReplaceAll(string(data), "https://keyhub.local", "http://"+r.Host)

	w.Header().Add("Content-Type", "application/json")
	w.Write([]byte(modded))
}

func routeOAuth2Token(w http.ResponseWriter, r *http.Request) {
	username, _, ok := r.BasicAuth()
	if !ok {
		fmt.Println("Basic Auth header missing")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	tokenFile := strings.ToLower(username) + "-token.json"

	writeJSONResponse(w, "../testdata/tokens/"+tokenFile)
}

func routeGroups(w http.ResponseWriter, r *http.Request) {
	accessToken, ok := parseBearerTokenAuth(r.Header)
	if !ok {
		fmt.Println("Bearer token missing")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	file := strings.ToLower(accessToken) + "-groups.json"

	data, err := ioutil.ReadFile("../testdata/groups/" + file)
	if err != nil {
		fmt.Println("File reading error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	modded := strings.ReplaceAll(string(data), "https://keyhub.local", "http://"+r.Host)
	w.Header().Add("Content-Type", "application/json")
	w.Write([]byte(modded))
}

func routeVaultRecords(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	group := vars["id"]
	file := "../testdata/records/group_" + group + "_records.json"

	writeJSONResponse(w, file)
}

func routeVaultRecord(w http.ResponseWriter, r *http.Request) {
	fmt.Println("record request detected")
	vars := mux.Vars(r)
	group := vars["id"]
	record := vars["uuid"]

	fmt.Println("record request", group, record)
	file := "../testdata/records/group_" + group + "_record_" + record + ".json"

	writeJSONResponse(w, file)
}

func writeJSONResponse(w http.ResponseWriter, file string) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println("File reading error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.Write(data)
}

func parseBearerTokenAuth(header http.Header) (string, bool) {
	authHeader := header["Authorization"]
	if len(authHeader) != 1 {
		fmt.Println("Authorization header missing")
		return "", false
	}

	parts := strings.Split(authHeader[0], " ")
	if len(parts) != 2 {
		fmt.Println("Invalid authorization header")
		return "", false
	}
	if "Bearer" != parts[0] {
		fmt.Println("Expected Bearer token authentication")
		return "", false
	}

	return parts[1], true
}

func testAPI(w http.ResponseWriter, r *http.Request) {

	if r.RequestURI == "/keyhub/rest/v1/group" {
		data, err := ioutil.ReadFile("../testdata/groups.json")
		if err != nil {
			fmt.Println("File reading error", err)
			return
		}
		modded := strings.ReplaceAll(string(data), "https://keyhub.local", "http://"+r.Host)
		w.Header().Add("Content-Type", "application/json")
		w.Write([]byte(modded))
		return
	}

	if r.RequestURI == "/keyhub/rest/v1/group/7531/vault/record?additional=audit" {
		data, err := ioutil.ReadFile("../testdata/group_7531_records.json")
		if err != nil {
			fmt.Println("File reading error", err)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		w.Write([]byte(data))
		return
	}

	if r.RequestURI == "/keyhub/rest/v1/group/7531/vault/record?additional=secret&uuid=2" {
		data, err := ioutil.ReadFile("../testdata/group_7531_record_2.json")
		if err != nil {
			fmt.Println("File reading error", err)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		w.Write([]byte(data))
		return
	}

	fmt.Println("no uri match")
	w.WriteHeader(http.StatusNotFound)
}
