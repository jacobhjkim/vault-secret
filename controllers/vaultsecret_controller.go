/*


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
	"os"
	"sort"
	"sync"
	"time"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	maupuv1beta1 "github.com/nmaupu/vault-secret/api/v1beta1"
	nmvault "github.com/nmaupu/vault-secret/pkg/vault"
	appVersion "github.com/nmaupu/vault-secret/pkg/version"
)

var (
	// secretsLastUpdateTime store last updated time of a secret to avoid reconciling too often
	// the same secret if it changes very fast (like with database KV backend or OTP)
	secretsLastUpdateTime      = make(map[string]time.Time)
	secretsLastUpdateTimeMutex sync.Mutex
)

const (
	// OperatorAppName is the name of the operator
	OperatorAppName = "vaultsecret-operator"
	// TimeFormat is the time format to indicate last updated field
	TimeFormat = "2006-01-02_15-04-05"
	// MinTimeMsBetweenSecretUpdate avoid a secret to be updated too often
	MinTimeMsBetweenSecretUpdate = time.Millisecond * 500
)

// VaultSecretReconciler reconciles a VaultSecret object
type VaultSecretReconciler struct {
	client.Client
	Log          logr.Logger
	Scheme       *runtime.Scheme
	LabelsFilter map[string]string
}

// +kubebuilder:rbac:groups=maupu.org,resources=vaultsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=maupu.org,resources=vaultsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch

// Reconcile reads that state of the cluster for a VaultSecret object and makes changes based on the state read
// and what is in the VaultSecret.Spec
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *VaultSecretReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("vaultsecret", req.NamespacedName)

	log.Info("Reconciling VaultSecret")

	// Fetch the VaultSecret CRInstance
	CRInstance := &maupuv1beta1.VaultSecret{}
	err := r.Get(ctx, req.NamespacedName, CRInstance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			log.Info("VaultSecret resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}

		// Error reading the object - requeue the request.
		log.Info(fmt.Sprintf("Error reading the VaultSecret object, requeuing, err=%v", err))
		return ctrl.Result{}, err
	}

	// Only updating stuff if two updates are not too close from each other
	// See secretsLastUpdateTime and MinTimeMsBetweenSecretUpdate variables
	updateTimeKey := fmt.Sprintf("%s/%s", CRInstance.GetNamespace(), CRInstance.Spec.SecretName)
	secretsLastUpdateTimeMutex.Lock()
	defer secretsLastUpdateTimeMutex.Unlock()
	ti := secretsLastUpdateTime[updateTimeKey] // no problem if it does not exist: it returns a default time.Time object (set to zero)
	now := time.Now()
	if now.Sub(ti) > MinTimeMsBetweenSecretUpdate {
		// Define a new Secret object from CR specs
		secretFromCR, err := r.newSecretForCR(CRInstance)
		if err != nil && secretFromCR == nil {
			// An error occurred, requeue
			log.Error(err, "An error occurred when creating secret from CR, requeuing.")
			return ctrl.Result{}, err
		} else if err != nil && secretFromCR != nil {
			// Some vault path and/or fields are not found, update CR (status) and requeue
			if updateErr := r.Status().Update(context.TODO(), CRInstance); updateErr != nil {
				log.Error(updateErr, fmt.Sprintf("Some errors occurred but CR cannot be updated, requeuing, original error=%v", err))
			} else {
				log.Error(err, "Some errors have been issued in the CR status information, please check, requeuing")
			}
			return ctrl.Result{}, err
		}

		// Everything's ok

		// Set VaultSecret CRInstance as the owner and controller
		if err = controllerutil.SetControllerReference(CRInstance, secretFromCR, r.Scheme); err != nil {
			log.Error(err, "An error occurred when setting controller reference, requeuing")
			return reconcile.Result{}, err
		}

		// Creating or updating secret resource from CR
		// Check if this Secret already exists
		found := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: secretFromCR.Name, Namespace: secretFromCR.Namespace}, found)
		if err != nil && errors.IsNotFound(err) {
			// Secret does not exist, creating it
			log.Info(fmt.Sprintf("Creating new Secret %s/%s", secretFromCR.Namespace, secretFromCR.Name))
			err = r.Create(ctx, secretFromCR)
		} else {
			// Secret already exists - updating
			log.Info(fmt.Sprintf("Reconciling existing Secret %s/%s", found.Namespace, found.Name))
			err = r.Update(ctx, secretFromCR)
		}

		// No problem creating or updating secret, updating CR info
		log.Info("Updating CR status information")
		if updateErr := r.Status().Update(ctx, CRInstance); updateErr != nil {
			log.Error(updateErr, "Error occurred when updating CR status")
		}

		// Updating "update time" at the very end to take into account all potential requeue requests from above
		secretsLastUpdateTime[updateTimeKey] = now
	}

	// finally returning given err (nil if no problem occurred, set to something otherwise)
	return ctrl.Result{RequeueAfter: CRInstance.Spec.SyncPeriod.Duration}, err
}

func (r *VaultSecretReconciler) newSecretForCR(cr *maupuv1beta1.VaultSecret) (*corev1.Secret, error) {
	log := r.Log.WithValues("func", "newSecretForCR")
	operatorName := os.Getenv("OPERATOR_NAME")
	if operatorName == "" {
		operatorName = OperatorAppName
	}
	labels := map[string]string{
		"app.kubernetes.io/name":       OperatorAppName,
		"app.kubernetes.io/version":    appVersion.Version,
		"app.kubernetes.io/managed-by": operatorName,
		"crName":                       cr.Name,
		"crNamespace":                  cr.Namespace,
		"lastUpdate":                   time.Now().Format(TimeFormat),
	}

	// Adding filtered labels
	for key, val := range r.LabelsFilter {
		labels[key] = val
	}

	secretName := cr.Spec.SecretName
	if secretName == "" {
		secretName = cr.Name
	}

	secretType := cr.Spec.SecretType
	if secretType == "" {
		secretType = "Opaque"
	}

	for key, val := range cr.Spec.SecretLabels {
		labels[key] = val
	}

	// Authentication provider
	authProvider, err := cr.GetVaultAuthProvider(r)
	if err != nil {
		return nil, err
	}

	// Processing vault login
	vaultConfig := nmvault.NewVaultConfig(cr.Spec.Config.Addr)
	vaultConfig.Namespace = cr.Spec.Config.Namespace
	vaultConfig.Insecure = cr.Spec.Config.Insecure
	vclient, err := authProvider.Login(vaultConfig)
	if err != nil {
		return nil, err
	}

	// Init
	hasError := false
	secrets := map[string][]byte{}

	// Clear status slice
	cr.Status.Entries = nil

	// Creating secret data from CR
	// Each secret entry in the CR will need a vault read to get filled.
	// If the KV/path remain the same, it's useless to call the vault again
	// as all fields are returned in the original read.
	// As a result, we are storing temporarily vault's data and use it as a "cache" to avoid
	// overloading the vault server.
	// This will be GC'ed at the end of the func
	cache := make(map[string](map[string]interface{}), 0)

	// Sort by secret keys to avoid updating the resource if order changes
	specSecrets := cr.Spec.Secrets
	sort.Sort(maupuv1beta1.BySecretKey(specSecrets))

	// Creating secret data from CR
	for _, s := range specSecrets {
		var err error
		errMessage := ""
		rootErrMessage := ""
		status := true

		// Vault read
		var sec map[string]interface{}
		cacheKey := fmt.Sprintf("%s/%s", s.KvPath, s.Path)
		if cacheVal, ok := cache[cacheKey]; ok {
			sec = cacheVal
			err = nil
		} else {
			log.Info(fmt.Sprintf("Reading from vault with the following info, path=%s, kvVersion=%d", cacheKey, s.KvVersion))
			sec, err = nmvault.Read(vclient, s.KvPath, s.Path, s.KvVersion)
			if err != nil || sec != nil { // only cache value if there is no error or a sec returned
				cache[cacheKey] = sec
			}
		}

		if err != nil {
			hasError = true
			if err != nil {
				rootErrMessage = err.Error()
			}
			errMessage = "Problem occurred getting secret"
			status = false
		} else if sec == nil || sec[s.Field] == nil || sec[s.Field] == "" {
			hasError = true
			if err != nil {
				rootErrMessage = err.Error()
			}
			errMessage = "Secret field not found in vault"
			status = false
		} else {
			status = true
			secrets[s.SecretKey] = ([]byte)(sec[s.Field].(string))
		}

		// Updating CR Status field
		cr.Status.Entries = append(cr.Status.Entries, maupuv1beta1.VaultSecretStatusEntry{
			Secret:    s,
			Status:    status,
			Message:   errMessage,
			RootError: rootErrMessage,
		})
	}

	// Handle return
	// Error is returned along with secret if it occurred at least once during loop
	// In case of error, we return a half populated secret object that caller has to handle itself
	var retErr error
	retErr = nil
	if hasError {
		retErr = fmt.Errorf("Secret %s cannot be created, see CR Status field for details", cr.Spec.SecretName)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Data: secrets,
		Type: secretType,
	}, retErr
}
