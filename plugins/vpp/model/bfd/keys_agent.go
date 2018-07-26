// Copyright (c) 2017 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bfd

const (
	// bfdSessionPrefix bfd-session/
	bfdSessionPrefix = "vpp/config/v1/bfd/session/"
	// bfdAuthKeysPrefix bfd-key/
	bfdAuthKeysPrefix = "vpp/config/v1/bfd/auth-key/"
	// BfdEchoFunctionPrefix bfd-echo-function/
	bfdEchoFunctionPrefix = "vpp/config/v1/bfd/echo-function"
)

// SessionKeyPrefix returns the prefix used in ETCD to store vpp bfd config.
func SessionKeyPrefix() string {
	return bfdSessionPrefix
}

// SessionKey returns the prefix used in ETCD to store vpp bfd config
// of a particular bfd session in selected vpp instance.
func SessionKey(bfdSessionIfaceLabel string) string {
	return bfdSessionPrefix + bfdSessionIfaceLabel
}

// AuthKeysKeyPrefix returns the prefix used in ETCD to store vpp bfd config.
func AuthKeysKeyPrefix() string {
	return bfdAuthKeysPrefix
}

// AuthKeysKey returns the prefix used in ETCD to store vpp bfd config
// of a particular bfd key in selected vpp instance.
func AuthKeysKey(bfdKeyIDLabel string) string {
	return bfdAuthKeysPrefix + bfdKeyIDLabel
}

// EchoFunctionKeyPrefix returns the prefix used in ETCD to store vpp bfd config.
func EchoFunctionKeyPrefix() string {
	return bfdEchoFunctionPrefix
}

// EchoFunctionKey returns the prefix used in ETCD to store vpp bfd config
// of a particular bfd echo function in selected vpp instance.
func EchoFunctionKey(bfdEchoIfaceLabel string) string {
	return bfdEchoFunctionPrefix + bfdEchoIfaceLabel
}
