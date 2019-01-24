/*
Copyright (c) 2017 SAP SE or an SAP affiliate company. All rights reserved.

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

// Package validation is used to validate all the machine CRD objects
package validation

import (
	"strings"

	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/machine-controller-manager/pkg/apis/machine"
)

// ValidateKubeVirtMachineClass validates a KubeVirtMachineClass and returns a list of errors.
func ValidateKubeVirtMachineClass(KubeVirtMachineClass *machine.KubeVirtMachineClass) field.ErrorList {
	return internalValidateKubeVirtMachineClass(KubeVirtMachineClass)
}

func internalValidateKubeVirtMachineClass(KubeVirtMachineClass *machine.KubeVirtMachineClass) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateKubeVirtMachineClassSpec(&KubeVirtMachineClass.Spec, field.NewPath("spec"))...)
	return allErrs
}

func validateKubeVirtMachineClassSpec(spec *machine.KubeVirtMachineClassSpec, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if "" == spec.PodNetworkCidr {
		allErrs = append(allErrs, field.Required(fldPath.Child("podNetworkCidr"), "PodNetworkCidr is required"))
	}

	allErrs = append(allErrs, validateSecretRef(spec.SecretRef, field.NewPath("spec.secretRef"))...)
	allErrs = append(allErrs, validateKubeVirtClassSpecTags(spec.Tags, field.NewPath("spec.tags"))...)

	return allErrs
}

func validateKubeVirtClassSpecTags(tags map[string]string, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	clusterName := ""
	nodeRole := ""

	for key := range tags {
		if strings.Contains(key, "kubernetes.io-cluster-") {
			clusterName = key
		} else if strings.Contains(key, "kubernetes.io-role-") {
			nodeRole = key
		}
	}

	if clusterName == "" {
		allErrs = append(allErrs, field.Required(fldPath.Child("kubernetes.io-cluster-"), "Tag required of the form kubernetes.io-cluster-****"))
	}
	if nodeRole == "" {
		allErrs = append(allErrs, field.Required(fldPath.Child("kubernetes.io-role-"), "Tag required of the form kubernetes.io-role-****"))
	}

	return allErrs
}
