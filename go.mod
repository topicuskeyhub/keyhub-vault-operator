module github.com/topicusonderwijs/keyhub-vault-operator

go 1.15

require (
	github.com/go-logr/logr v0.3.0
	github.com/gorilla/mux v1.8.0
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.2
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/topicuskeyhub/go-keyhub v0.2.1
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	gopkg.in/yaml.v1 v1.0.0-20140924161607-9f9df34309c0
	k8s.io/api v0.19.2
	k8s.io/apimachinery v0.19.2
	k8s.io/client-go v0.19.2
	sigs.k8s.io/controller-runtime v0.7.0
	software.sslmate.com/src/go-pkcs12 v0.0.0-20210222215041-dec221a1a07f
)
