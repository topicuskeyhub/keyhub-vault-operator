package secret

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"log"
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

	if len(ks.Spec.Data) == 1 {
		privateKey, certificate, caCerts, err = sb.loadCertificateBundle(&ks.Status, ks.Spec.Data[0])
	} else {
		privateKey, certificate, caCerts, err = sb.loadCertificateBlocks(&ks.Status, ks.Spec.Data)
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

	// 		err = api.SetSecretKeyStatus(&ks.Status.SecretKeyStatuses, ref.Name, secret.Data[ref.Name])
	// if err != nil {
	// 	// event + err @ end
	// 	continue
	// }

	return nil
}

func (sb *secretBuilder) loadCertificateBundle(status *v1alpha1.KeyHubSecretStatus, ref keyhubv1alpha1.SecretKeyReference) (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, err error) {
	if ref.Name != "pem" && ref.Name != "pkcs12" {
		return nil, nil, nil, fmt.Errorf("Invalid name '%s', only 'pem' or 'pkcs12' is allowed for single key TLS secret", ref.Name)
	}

	idxEntry, ok := sb.records[ref.Record]
	if !ok {
		return nil, nil, nil, fmt.Errorf("Record %s not found for key %s", ref.Record, ref.Name)
	}

	// checks
	// keyhub update? last modified at vergelijken?
	state := api.FindVaultRecordStatus(status.VaultRecordStatuses, idxEntry.Record.UUID)
	if state != nil && !idxEntry.Record.LastModifiedAt().After(state.LastModifiedAt.Time) {
		log.Println("no update detected in keyhub")
		return nil, nil, nil, nil
	}
	// certState := api.FindSecretKeyStatus(status.SecretKeyStatuses, corev1.TLSCertKey)
	// if certState != nil &&

	// bcrypt.CompareHashAndPassword(certstate.Hash, ref.)// moeten secret hebben voor value van de key

	// idxEntry.Record, statuses

	record, err := sb.retriever.Get(idxEntry)
	if err != nil {
		return nil, nil, nil, err
	}

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

	fmt.Println("pem", "cert", len(certificates))

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

func (sb *secretBuilder) loadCertificateBlocks(status *v1alpha1.KeyHubSecretStatus, refs []keyhubv1alpha1.SecretKeyReference) (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, err error) {
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

	privateKeyRecord, err := sb.retriever.Get(privateKeyIdxEntry)
	if err != nil {
		return nil, nil, nil, err
	}

	// 		if len(keyRecord.File()) == 0 {
	// 			return fmt.Errorf("Missing file for record %s", keyRef.Record)
	// 		}

	certificateRecord, err := sb.retriever.Get(certificateIdxEntry)
	if err != nil {
		return nil, nil, nil, err
	}

	// 		if len(crtRecord.File()) == 0 {
	// 			return fmt.Errorf("Missing file for record %s", certRef.Record)
	// 		}
	sb.log.Info("checking ca certs", "ca name", caCertsRef.Name)
	var caCertsRecord *keyhub.VaultRecord
	if caCertsRef.Name != "" {
		if caCertsRecord, err = sb.retriever.Get(caCertsIdxEntry); err != nil {
			sb.log.Info("error ophalen ca certs record")
			return nil, nil, nil, err
		}

		// 		if len(crtRecord.File()) == 0 {
		// 			return fmt.Errorf("Missing file for record %s", certRef.Record)
		// 		}
	}

	if privateKey, err = keyUtil.ParsePrivateKeyPEM(privateKeyRecord.File()); err != nil {
		return nil, nil, nil, err
	}

	certificates, err := certUtil.ParseCertsPEM(certificateRecord.File())
	if err != nil {
		return nil, nil, nil, err
	}
	sb.log.Info("cert en key correct")

	if len(certificates) == 1 {
		certificate = certificates[0]
		if caCertsRef.Name != "" {
			if caCerts, err = certUtil.ParseCertsPEM(caCertsRecord.File()); err != nil {
				sb.log.Info("hier dus error")
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
