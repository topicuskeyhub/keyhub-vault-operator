// Copyright 2020 Topicus Security BV
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	keyhubv1alpha1 "github.com/topicuskeyhub/keyhub-vault-operator/api/v1alpha1"
	"github.com/topicuskeyhub/keyhub-vault-operator/controllers/metrics"
	"github.com/topicuskeyhub/keyhub-vault-operator/controllers/policy"
	"github.com/topicuskeyhub/keyhub-vault-operator/controllers/secret"
	"github.com/topicuskeyhub/keyhub-vault-operator/controllers/settings"
	"github.com/topicuskeyhub/keyhub-vault-operator/controllers/vault"
)

const (
	requeueDelay           = time.Duration(5 * time.Minute)
	requeueDelayAfterError = time.Duration(2 * time.Minute)
)

// KeyHubSecretReconciler reconciles a KeyHubSecret object
type KeyHubSecretReconciler struct {
	client.Client
	Log             logr.Logger
	Scheme          *runtime.Scheme
	Recorder        record.EventRecorder
	SettingsManager settings.SettingsManager
	PolicyEngine    policy.PolicyEngine
	VaultIndexCache vault.VaultIndexCache
}

func init() {
	metrics.KeyHubApiRequests.WithLabelValues("group", "list").Add(0)
	metrics.KeyHubApiRequests.WithLabelValues("vault", "list").Add(0)
	metrics.KeyHubApiRequests.WithLabelValues("vault", "get").Add(0)
}

// +kubebuilder:rbac:groups=keyhub.topicus.nl,resources=keyhubsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=keyhub.topicus.nl,resources=keyhubsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=keyhub.topicus.nl,resources=keyhubsecrets/finalizers,verbs=update

// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the KeyHubSecret object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.7.0/pkg/reconcile
func (r *KeyHubSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("keyhubsecret", req.NamespacedName)
	// r.Recorder.Event()

	log.Info("", "KeyHubSecret", req.NamespacedName)

	// Fetch the KeyHubSecret instance
	keyhubsecret := &keyhubv1alpha1.KeyHubSecret{}
	err := r.Get(ctx, req.NamespacedName, keyhubsecret)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			log.Info("KeyHubSecret resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get KeyHubSecret")
		return ctrl.Result{}, err
	}

	if keyhubsecret.DeletionTimestamp != nil {
		log.Info("KeyHubSecret resource marked for deletion. Ignoring since object must be deleted")
		return ctrl.Result{}, nil
	}

	secret := r.newSecretForCR(keyhubsecret)
	res, err := controllerutil.CreateOrPatch(ctx, r.Client, secret, r.reconcileFn(keyhubsecret, secret))
	if err != nil {
		keyhubsecret.Status.Sync.Status = keyhubv1alpha1.SyncStatusCodeOutOfSync
		r.Status().Update(ctx, keyhubsecret)
		r.Recorder.Event(keyhubsecret, "Warning", "ProcessingError", err.Error())
		log.Error(err, "sync failed")
		return ctrl.Result{RequeueAfter: requeueDelayAfterError}, err
	}

	if res != controllerutil.OperationResultNone {
		var reason string
		var message string
		switch res {
		case controllerutil.OperationResultCreated:
			reason = "SecretCreated"
			message = fmt.Sprintf("Secret (type '%s') has been created", secret.Type)
		default:
			reason = "SecretUpdated"
			message = "Secret has been updated"
		}
		r.Recorder.Event(keyhubsecret, "Normal", reason, message)
	}

	if len(keyhubsecret.Status.SecretKeyStatuses) > 0 {
		keyhubsecret.Status.Sync.Status = keyhubv1alpha1.SyncStatusCodeSynced
	} else {
		keyhubsecret.Status.Sync.Status = keyhubv1alpha1.SyncStatusCodeUnknown
	}

	err = r.Status().Update(ctx, keyhubsecret)
	if err != nil {
		log.Error(err, "Failed to update KeyHubSecret status")
		r.Recorder.Event(keyhubsecret, "Warning", "FailedUpdate", err.Error())
		return ctrl.Result{RequeueAfter: requeueDelayAfterError}, err
	}

	return ctrl.Result{RequeueAfter: requeueDelay}, nil
}

func (r *KeyHubSecretReconciler) reconcileFn(cr *keyhubv1alpha1.KeyHubSecret, s *corev1.Secret) controllerutil.MutateFn {
	return func() error {
		// Set KeyHubSecret instance as the owner and controller
		if err := controllerutil.SetControllerReference(cr, s, r.Scheme); err != nil {
			return err
		}

		client, err := r.PolicyEngine.GetClient(cr)
		if err != nil {
			return err
		}

		records, err := r.VaultIndexCache.Get(client)
		if err != nil {
			return err
		}

		secretBuilder := secret.NewSecretBuilder(
			r.Client,
			ctrl.Log.WithName("SecretBuilder"),
			records,
			vault.NewVaultSecretRetriever(r.Log, client),
		)

		return secretBuilder.Build(cr, s)
	}
}

func (r *KeyHubSecretReconciler) newSecretForCR(cr *keyhubv1alpha1.KeyHubSecret) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Name,
			Namespace: cr.Namespace,
		},
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeyHubSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&keyhubv1alpha1.KeyHubSecret{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
