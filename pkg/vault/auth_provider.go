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

package vault

import (
	vapi "github.com/hashicorp/vault/api"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var (
	log = logf.Log.WithName("vault-auth-provider")
)

type VaultConfig struct {
	Address   string
	Namespace string
	Insecure  bool
}

func NewVaultConfig(address string) *VaultConfig {
	return &VaultConfig{
		Address:   address,
		Namespace: "",
		Insecure:  false,
	}
}

type VaultAuthProvider interface {
	Login(*VaultConfig) (*vapi.Client, error)
}
