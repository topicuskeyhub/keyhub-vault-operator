package secret

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"time"

	// "golang.org/x/crypto/bcrypt"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/topicuskeyhub/go-keyhub"
	"github.com/topicusonderwijs/keyhub-vault-operator/api"
	"github.com/topicusonderwijs/keyhub-vault-operator/api/v1alpha1"
	keyhubv1alpha1 "github.com/topicusonderwijs/keyhub-vault-operator/api/v1alpha1"
	"github.com/topicusonderwijs/keyhub-vault-operator/controllers/vault"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	certUtil "k8s.io/client-go/util/cert"
	keyUtil "k8s.io/client-go/util/keyutil"
)

const (
	TLSCAKey = "ca.crt"
)

func (sb *secretBuilder) applyTLSSecretData(ks *keyhubv1alpha1.KeyHubSecret, secret *corev1.Secret) error {
	if len(ks.Spec.Data) < 1 || len(ks.Spec.Data) > 3 {
		return fmt.Errorf("Unexpected number of keys for TLS secret, found %d keys", len(ks.Spec.Data))
	}

	var privateKey interface{}
	var certificate *x509.Certificate
	var caCerts []*x509.Certificate
	var err error

	name := types.NamespacedName{
		Name:      ks.Name,
		Namespace: ks.Namespace,
	}

	if len(ks.Spec.Data) == 1 {
		privateKey, certificate, caCerts, err = sb.loadCertificateBundle(name, &ks.Status, ks.Spec.Data[0], secret.Data)
	} else {
		privateKey, certificate, caCerts, err = sb.loadCertificateBlocks(name, &ks.Status, ks.Spec.Data, secret.Data)
	}
	if err != nil {
		return err
	}
	if privateKey == nil && certificate == nil && caCerts == nil {
		// no changes
		return nil
	}

	certBytes, err := certUtil.EncodeCertificates(append([]*x509.Certificate{certificate}, caCerts...)...)
	if err != nil {
		return err
	}

	keyBytes, err := keyUtil.MarshalPrivateKeyToPEM(privateKey.(*rsa.PrivateKey))
	if err != nil {
		return err
	}

	secret.Data = map[string][]byte{
		corev1.TLSCertKey:       certBytes,
		corev1.TLSPrivateKeyKey: keyBytes,
	}

	sb.applyRancherCertificateAnnotations(certificate, secret)

	err = api.SetSecretKeyStatus(&ks.Status.SecretKeyStatuses, corev1.TLSCertKey, certBytes)
	if err != nil {
		// event + err @ end
		return err
	}
	err = api.SetSecretKeyStatus(&ks.Status.SecretKeyStatuses, corev1.TLSPrivateKeyKey, keyBytes)
	if err != nil {
		// event + err @ end
		return err
	}

	return nil
}

func (sb *secretBuilder) loadCertificateBundle(keyhubSecretName types.NamespacedName, status *v1alpha1.KeyHubSecretStatus, ref keyhubv1alpha1.SecretKeyReference, data map[string][]byte) (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, err error) {
	if ref.Name != "pem" && ref.Name != "pkcs12" {
		return nil, nil, nil, fmt.Errorf("Invalid name '%s', only 'pem' or 'pkcs12' is allowed for single key TLS secret", ref.Name)
	}

	idxEntry, ok := sb.records[ref.Record]
	if !ok {
		return nil, nil, nil, fmt.Errorf("Record %s not found for key %s", ref.Record, ref.Name)
	}

	// Check whether or not the Secret needs updating
	recordChanged := api.IsVaulRecordChanged(status.VaultRecordStatuses, &idxEntry.Record)
	secretDataChanged :=
		api.IsSecretKeyChanged(status.SecretKeyStatuses, data, corev1.TLSPrivateKeyKey) ||
			api.IsSecretKeyChanged(status.SecretKeyStatuses, data, corev1.TLSCertKey)
	if !recordChanged && !secretDataChanged {
		return nil, nil, nil, nil
	}

	sb.log.Info("Syncing KeyHub vault record", "keyhubsecret", keyhubSecretName.String())
	record, err := sb.retriever.Get(idxEntry)
	if err != nil {
		return nil, nil, nil, err
	}

	status.VaultRecordStatuses = []keyhubv1alpha1.VaultRecordStatus{}
	api.SetVaultRecordStatus(&status.VaultRecordStatuses, record)

	switch ref.Name {
	case "pem":
		return sb.parsePEM(record.File(), record.Password())
	case "pkcs12":
		return pkcs12.DecodeChain(record.File(), record.Password())
	default:
		return nil, nil, nil, fmt.Errorf("Unsupported certificate bundle type: %s", ref.Name)
	}
}

func (sb *secretBuilder) parsePEM(pemData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, err error) {
	certificates, err := certUtil.ParseCertsPEM(pemData)
	if err != nil {
		return nil, nil, nil, err
	}

	if len(certificates) < 1 {
		return nil, nil, nil, fmt.Errorf("No certificate found")
	}

	certificate = certificates[0]
	if len(certificates) > 1 {
		caCerts = certificates[1:]
	} else {
		caCerts = make([]*x509.Certificate, 0)
	}

	if privateKey, err = keyUtil.ParsePrivateKeyPEM(pemData); err != nil {
		return nil, nil, nil, err
	}

	return
}

func (sb *secretBuilder) loadCertificateBlocks(keyhubSecretName types.NamespacedName, status *v1alpha1.KeyHubSecretStatus, refs []keyhubv1alpha1.SecretKeyReference, data map[string][]byte) (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, err error) {
	var privateKeyRef, certificateRef, caCertsRef keyhubv1alpha1.SecretKeyReference
	for _, ref := range refs {
		switch ref.Name {
		case corev1.TLSPrivateKeyKey:
			privateKeyRef = ref
		case corev1.TLSCertKey:
			certificateRef = ref
		case TLSCAKey:
			caCertsRef = ref
		}
	}

	if privateKeyRef.Name == "" {
		return nil, nil, nil, fmt.Errorf("Missing key '%s' for TLS secret", corev1.TLSPrivateKeyKey)
	}
	if certificateRef.Name == "" {
		return nil, nil, nil, fmt.Errorf("Missing key '%s' for TLS secret", corev1.TLSCertKey)
	}

	privateKeyIdxEntry, ok := sb.records[privateKeyRef.Record]
	if !ok {
		return nil, nil, nil, fmt.Errorf("Record %s not found for privatekey", privateKeyRef.Record)
	}

	certificateIdxEntry, ok := sb.records[certificateRef.Record]
	if !ok {
		return nil, nil, nil, fmt.Errorf("Record %s not found for certificate", certificateRef.Record)
	}

	var caCertsIdxEntry vault.VaultRecordWithGroup
	if caCertsRef.Name != "" {
		if caCertsIdxEntry, ok = sb.records[caCertsRef.Record]; !ok {
			return nil, nil, nil, fmt.Errorf("Record %s not found for ca certificates", caCertsRef.Record)
		}
	}

	// Check whether or not the Secret needs updating
	privateKeyStatus := api.FindVaultRecordStatus(status.VaultRecordStatuses, privateKeyRef.Record)
	privateKeyChanged := privateKeyStatus == nil || privateKeyIdxEntry.Record.LastModifiedAt().After(privateKeyStatus.LastModifiedAt.Time)
	certificateStatus := api.FindVaultRecordStatus(status.VaultRecordStatuses, certificateRef.Record)
	certificateChanged := certificateStatus == nil || certificateIdxEntry.Record.LastModifiedAt().After(certificateStatus.LastModifiedAt.Time)
	caCertsChanged := false
	if caCertsRef.Name == "" {
		caCertsChanged = len(status.VaultRecordStatuses) == 3 // CACerts key removed
	} else {
		caCertsStatus := api.FindVaultRecordStatus(status.VaultRecordStatuses, caCertsRef.Record)
		caCertsChanged = caCertsStatus == nil || caCertsIdxEntry.Record.LastModifiedAt().After(caCertsStatus.LastModifiedAt.Time)
	}
	secretDataChanged :=
		api.IsSecretKeyChanged(status.SecretKeyStatuses, data, corev1.TLSPrivateKeyKey) ||
			api.IsSecretKeyChanged(status.SecretKeyStatuses, data, corev1.TLSCertKey)
	if !privateKeyChanged && !certificateChanged && !caCertsChanged && !secretDataChanged {
		return nil, nil, nil, nil
	}

	status.VaultRecordStatuses = []keyhubv1alpha1.VaultRecordStatus{}

	sb.log.Info("Syncing KeyHub vault record(s)", "keyhubsecret", keyhubSecretName.String())

	privateKeyRecord, err := sb.retriever.Get(privateKeyIdxEntry)
	if err != nil {
		return nil, nil, nil, err
	}

	if len(privateKeyRecord.File()) == 0 {
		return nil, nil, nil, fmt.Errorf("Missing file for record %s", privateKeyRef.Record)
	}

	if privateKey, err = keyUtil.ParsePrivateKeyPEM(privateKeyRecord.File()); err != nil {
		return nil, nil, nil, err
	}

	api.SetVaultRecordStatus(&status.VaultRecordStatuses, privateKeyRecord)

	certificateRecord, err := sb.retriever.Get(certificateIdxEntry)
	if err != nil {
		return nil, nil, nil, err
	}

	if len(certificateRecord.File()) == 0 {
		return nil, nil, nil, fmt.Errorf("Missing file for record %s", certificateRef.Record)
	}

	certificates, err := certUtil.ParseCertsPEM(certificateRecord.File())
	if err != nil {
		return nil, nil, nil, err
	}

	api.SetVaultRecordStatus(&status.VaultRecordStatuses, certificateRecord)

	var caCertsRecord *keyhub.VaultRecord
	if caCertsRef.Name != "" {
		if caCertsRecord, err = sb.retriever.Get(caCertsIdxEntry); err != nil {
			return nil, nil, nil, err
		}

		if len(caCertsRecord.File()) == 0 {
			return nil, nil, nil, fmt.Errorf("Missing file for record %s", caCertsRef.Record)
		}

		api.SetVaultRecordStatus(&status.VaultRecordStatuses, caCertsRecord)
	}

	if len(certificates) == 1 {
		certificate = certificates[0]
		if caCertsRef.Name != "" {
			if caCerts, err = certUtil.ParseCertsPEM(caCertsRecord.File()); err != nil {
				return nil, nil, nil, err
			}
		}
	} else {
		certificate = certificates[0]
		caCerts = certificates[1:]
	}

	return
}

// Rancher 2.0 support
func (sb *secretBuilder) applyRancherCertificateAnnotations(cert *x509.Certificate, secret *corev1.Secret) {
	secret.GetAnnotations()["field.cattle.io/algorithm"] = keyAlgorithmLookup[cert.PublicKeyAlgorithm]
	secret.GetAnnotations()["field.cattle.io/certFingerprint"] = strings.Replace(fmt.Sprintf("% X", sha1.Sum(cert.Raw)), " ", ":", -1)
	secret.GetAnnotations()["field.cattle.io/cn"] = cert.Subject.CommonName
	secret.GetAnnotations()["field.cattle.io/expiresAt"] = cert.NotAfter.UTC().Format(time.RFC3339)
	secret.GetAnnotations()["field.cattle.io/issuedAt"] = cert.NotBefore.UTC().Format(time.RFC3339)
	secret.GetAnnotations()["field.cattle.io/issuer"] = cert.Issuer.CommonName
	secret.GetAnnotations()["field.cattle.io/serialNumber"] = cert.SerialNumber.String()
	secret.GetAnnotations()["field.cattle.io/version"] = strconv.Itoa(cert.Version)

	var publicKeySize int
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		publicKeySize = pub.N.BitLen()
	case *dsa.PublicKey:
		publicKeySize = pub.Q.BitLen()
	case *ecdsa.PublicKey:
		publicKeySize = pub.X.BitLen()
	}
	secret.GetAnnotations()["field.cattle.io/keySize"] = strconv.Itoa(publicKeySize)

	var subjectAlternativeNames []string
	for _, name := range cert.DNSNames {
		subjectAlternativeNames = append(subjectAlternativeNames, strconv.Quote(name))
	}
	for _, ip := range cert.IPAddresses {
		subjectAlternativeNames = append(subjectAlternativeNames, strconv.Quote(ip.String()))
	}
	secret.GetAnnotations()["field.cattle.io/subjectAlternativeNames"] = fmt.Sprintf("[%s]", strings.Join(subjectAlternativeNames, ","))
}

var keyAlgorithmLookup = map[x509.PublicKeyAlgorithm]string{
	x509.RSA:   "RSA",
	x509.DSA:   "DSA",
	x509.ECDSA: "ECDSA",
}
