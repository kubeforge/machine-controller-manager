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

	if "" == spec.ImageName {
		allErrs = append(allErrs, field.Required(fldPath.Child("imageName"), "imageName is required"))
	}
	if "" == spec.Memory {
		allErrs = append(allErrs, field.Required(fldPath.Child("memory"), "memory is required"))
	}
	if "" == spec.Cores {
		allErrs = append(allErrs, field.Required(fldPath.Child("cores"), "cores is required"))
	}
	if "" == spec.PodNetworkCidr {
		allErrs = append(allErrs, field.Required(fldPath.Child("podNetworkCidr"), "PodNetworkCidr is required"))
	}

	allErrs = append(allErrs, validateKubeVirtDisks(spec.Disks, field.NewPath("spec.disks"))...)
	allErrs = append(allErrs, validateKubeVirtNetworkInterfaces(spec.Networks, field.NewPath("spec.networks"))...)
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

func validateKubeVirtDisks(disks []*machine.KubeVirtDisk, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	for i, disk := range disks {
		idxPath := fldPath.Index(i)
		if disk.Name == "" {
			allErrs = append(allErrs, field.Invalid(idxPath.Child("name"), disk.Name, "name is required for disk"))
		}
		if disk.Type == "" {
			allErrs = append(allErrs, field.Invalid(idxPath.Child("type"), disk.Type, "type is required for disk"))
		}
		if disk.VolumeRef == "" {
			allErrs = append(allErrs, field.Invalid(idxPath.Child("volumeRef"), disk.VolumeRef, "volumeRef is required for disk"))
		}
	}

	return allErrs
}

func validateKubeVirtNetworkInterfaces(nets []*machine.KubeVirtNetworkInterface, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	for i, net := range nets {
		idxPath := fldPath.Index(i)
		if net.Name == "" {
			allErrs = append(allErrs, field.Invalid(idxPath.Child("name"), net.Name, "name is required for network"))
		}
		if net.NetworkType == "" {
			allErrs = append(allErrs, field.Invalid(idxPath.Child("networkType"), net.NetworkType, "networkType is required for network"))
		}
	}

	return allErrs
}
