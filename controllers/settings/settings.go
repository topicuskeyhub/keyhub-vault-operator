// Copyright 2020 Topicus Security BV
// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	controllerSecret = "keyhub-vault-operator-secret"

	settingsURI          = "uri"
	settingsClientID     = "clientId"
	settingsClientSecret = "clientSecret"
)

type ControllerSettings struct {
	URI          string
	ClientID     string
	ClientSecret string
}

type SettingsManager interface {
	GetSettings() (*ControllerSettings, error)
}

type settingsManager struct {
	client client.Client
	log    logr.Logger
}

func CreateSettingsManager(client client.Client, log logr.Logger) SettingsManager {
	return &settingsManager{
		client: client,
		log:    log,
	}
}

func (mgr *settingsManager) GetSettings() (*ControllerSettings, error) {
	operatorNamespace := getOperatorNamespace()
	mgr.log.Info("Loading settings", "secret", fmt.Sprintf("%s/%s", operatorNamespace, controllerSecret))
	key := types.NamespacedName{Namespace: operatorNamespace, Name: controllerSecret}
	secret := &corev1.Secret{}
	err := mgr.client.Get(context.TODO(), key, secret)
	if err != nil {
		return nil, err
	}

	var settings ControllerSettings
	if err := updateSettingsFromSecret(&settings, secret); err != nil {
		return nil, err
	}

	return &settings, nil
}

func updateSettingsFromSecret(settings *ControllerSettings, secret *corev1.Secret) error {
	if uri := secret.Data[settingsURI]; len(uri) > 0 {
		settings.URI = string(uri)
	} else {
		return errors.New("uri is missing")
	}

	clientID := secret.Data[settingsClientID]
	clientSecret := secret.Data[settingsClientSecret]
	if len(clientID) > 0 && len(clientSecret) > 0 {
		settings.ClientID = string(clientID)
		settings.ClientSecret = string(clientSecret)
	} else {
		return errors.New("client credentials are missing")
	}

	return nil
}

func getOperatorNamespace() string {
	// Fall back to the namespace associated with the service account token, if available
	if data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
			return ns
		}
	}

	return "default"
}
