module github.com/topicusonderwijs/keyhub-vault-operator

go 1.16

require (
	github.com/go-logr/logr v0.4.0
	github.com/gorilla/mux v1.8.0
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.16.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/prometheus/client_golang v1.11.0
	github.com/topicuskeyhub/go-keyhub v0.2.1
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.22.1
	k8s.io/apimachinery v0.22.1
	k8s.io/client-go v0.22.1
	sigs.k8s.io/controller-runtime v0.9.6
	software.sslmate.com/src/go-pkcs12 v0.0.0-20210415151418-c5206de65a78
)
