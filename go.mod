module github.com/topicusonderwijs/keyhub-vault-operator

go 1.16

require (
	github.com/go-logr/logr v0.4.0
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.17.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/prometheus/client_golang v1.11.0
	github.com/topicuskeyhub/go-keyhub v1.0.0
	golang.org/x/crypto v0.0.0-20220112180741-5e0467b6c7ce
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.22.4
	k8s.io/apimachinery v0.22.4
	k8s.io/client-go v0.22.4
	sigs.k8s.io/controller-runtime v0.10.3
	software.sslmate.com/src/go-pkcs12 v0.0.0-20210415151418-c5206de65a78
)
