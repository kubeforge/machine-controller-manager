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

// Package driver contains the cloud provider specific implementations to manage machines
package driver

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	v1alpha1 "github.com/gardener/machine-controller-manager/pkg/apis/machine/v1alpha1"
	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	kubevirtv1 "kubevirt.io/kubevirt/pkg/api/v1"
	"kubevirt.io/kubevirt/pkg/kubecli"
)

const (
	containerDiskName        = "containerdisk"
	cloudInitDiskName        = "cloudinitdisk"
	networkTypeGenie         = "genie"
	networkTypeMultus        = "multus"
	networkTypePod           = "pod"
	volumeTypeConfigMap      = "configMap"
	volumeTypeDataVolume     = "dataVolume"
	volumeTypePVC            = "persistentVolumeClaim"
	volumeTypeSecret         = "secret"
	volumeTypeServiceAccount = "serviceAccount"
)

// KubeVirtDriver is the driver struct for holding KubeVirt machine information
type KubeVirtDriver struct {
	KubeVirtMachineClass *v1alpha1.KubeVirtMachineClass
	CloudConfig          *corev1.Secret
	UserData             string
	MachineID            string
	MachineName          string
}

// Create method is used to create an KubeVirt machine
func (d *KubeVirtDriver) Create() (string, string, error) {
	kubevirt, namespace, err := d.createKubevirtClient()
	if err != nil {
		return "", "", fmt.Errorf("Failed to create KubeVirt client: %v", err)
	}

	labels := d.KubeVirtMachineClass.Spec.Tags
	memory, err := resource.ParseQuantity(d.KubeVirtMachineClass.Spec.Memory)
	if err != nil {
		return "", "", fmt.Errorf("Failed to parse memory quantity for machine: %v", err)
	}
	// Use the numbers of cores for cpu resource request
	cpu, err := resource.ParseQuantity(d.KubeVirtMachineClass.Spec.Cores)
	if err != nil {
		return "", "", fmt.Errorf("Failed to parse cpu quantity for machine: %v", err)
	}
	cores, err := strconv.ParseUint(d.KubeVirtMachineClass.Spec.Cores, 10, 32)
	if err != nil {
		return "", "", fmt.Errorf("Failed to parse cpu cores for machine: %v", err)
	}
	image := d.KubeVirtMachineClass.Spec.ImageName
	disks := d.KubeVirtMachineClass.Spec.Disks
	networks := d.KubeVirtMachineClass.Spec.Networks

	instance := &kubevirtv1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      d.MachineName,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: kubevirtv1.VirtualMachineInstanceSpec{
			Domain: kubevirtv1.DomainSpec{
				CPU: &kubevirtv1.CPU{
					Cores: uint32(cores),
				},
				Resources: kubevirtv1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    cpu,
						corev1.ResourceMemory: memory,
					},
				},
				Devices: kubevirtv1.Devices{
					Disks: []kubevirtv1.Disk{
						kubevirtv1.Disk{
							Name: containerDiskName,
						},
					},
					Interfaces: []kubevirtv1.Interface{},
				},
			},
			Networks: []kubevirtv1.Network{},
			Volumes: []kubevirtv1.Volume{
				kubevirtv1.Volume{
					Name: containerDiskName,
					VolumeSource: kubevirtv1.VolumeSource{
						ContainerDisk: &kubevirtv1.ContainerDiskSource{
							Image: image,
						},
					},
				},
			},
		},
	}

	var secret *corev1.Secret
	if d.UserData != "" {
		secret, err = d.ensureUserDataSecret(kubevirt, namespace)
		if err != nil {
			return "", "", err
		}
		d.attachCloudInitDisk(instance, secret.ObjectMeta.Name)
	}

	for _, disk := range disks {
		err := d.attachDisk(instance, disk)
		if err != nil {
			return "", "", err
		}
	}

	for _, network := range networks {
		err := d.attachNetworkInterface(instance, network)
		if err != nil {
			return "", "", err
		}
	}

	vmi, err := kubevirt.VirtualMachineInstance(namespace).Create(instance)
	if err != nil {
		return "", "", fmt.Errorf("Failed to create machine: %v", err)
	}

	d.MachineID = d.encodeMachineID(vmi.ObjectMeta.Name)
	glog.V(3).Infof("Created machine with ID: %s", d.MachineID)

	if d.UserData != "" {
		// Reference this new VMI as owner of the userdata secret
		secret.ObjectMeta.OwnerReferences = append(secret.ObjectMeta.OwnerReferences, metav1.OwnerReference{
			APIVersion: vmi.TypeMeta.APIVersion,
			Kind:       vmi.TypeMeta.Kind,
			Name:       vmi.ObjectMeta.Name,
			UID:        vmi.ObjectMeta.UID,
		})
		_, err := kubevirt.CoreV1().Secrets(secret.ObjectMeta.Namespace).Update(secret)
		if err != nil {
			glog.V(3).Infof("Failed to add machine %s as owner of secret %s", vmi.ObjectMeta.Name, secret.ObjectMeta.Name)
		}
	}
	return d.MachineID, d.MachineName, nil

}

func (d *KubeVirtDriver) attachCloudInitDisk(vmi *kubevirtv1.VirtualMachineInstance, secretRef string) {
	vmi.Spec.Domain.Devices.Disks = append(vmi.Spec.Domain.Devices.Disks, kubevirtv1.Disk{
		Name: cloudInitDiskName,
	})
	vmi.Spec.Volumes = append(vmi.Spec.Volumes, kubevirtv1.Volume{
		Name: cloudInitDiskName,
		VolumeSource: kubevirtv1.VolumeSource{
			CloudInitConfigDrive: &kubevirtv1.CloudInitConfigDriveSource{
				UserDataSecretRef: &corev1.LocalObjectReference{
					Name: secretRef,
				},
			},
		},
	})
}

func (d *KubeVirtDriver) attachDisk(vmi *kubevirtv1.VirtualMachineInstance, disk *v1alpha1.KubeVirtDisk) error {
	if disk.Name == "" {
		return fmt.Errorf("Cannot attach disk without name")
	}
	if disk.VolumeRef == "" {
		return fmt.Errorf("Missing volume reference for disk %s", disk.Name)
	}

	var volumeSource kubevirtv1.VolumeSource
	switch disk.Type {
	case volumeTypeConfigMap:
		volumeSource = kubevirtv1.VolumeSource{
			ConfigMap: &kubevirtv1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: disk.VolumeRef,
				},
			},
		}
	case volumeTypeDataVolume:
		volumeSource = kubevirtv1.VolumeSource{
			DataVolume: &kubevirtv1.DataVolumeSource{
				Name: disk.VolumeRef,
			},
		}
	case volumeTypePVC:
		volumeSource = kubevirtv1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: disk.VolumeRef,
			},
		}
	case volumeTypeSecret:
		volumeSource = kubevirtv1.VolumeSource{
			Secret: &kubevirtv1.SecretVolumeSource{
				SecretName: disk.VolumeRef,
			},
		}
	case volumeTypeServiceAccount:
		volumeSource = kubevirtv1.VolumeSource{
			ServiceAccount: &kubevirtv1.ServiceAccountVolumeSource{
				ServiceAccountName: disk.VolumeRef,
			},
		}
	default:
		return fmt.Errorf("Unsupported disk type '%s'", disk.Type)
	}

	vmi.Spec.Domain.Devices.Disks = append(vmi.Spec.Domain.Devices.Disks, kubevirtv1.Disk{
		Name: disk.Name,
	})
	vmi.Spec.Volumes = append(vmi.Spec.Volumes, kubevirtv1.Volume{
		Name:         disk.Name,
		VolumeSource: volumeSource,
	})

	if disk.Serial != "" {
		vmi.Spec.Domain.Devices.Disks[len(vmi.Spec.Domain.Devices.Disks)-1].Serial = disk.Serial
	}

	return nil
}

func (d *KubeVirtDriver) attachNetworkInterface(vmi *kubevirtv1.VirtualMachineInstance, net *v1alpha1.KubeVirtNetworkInterface) error {
	if net.Name == "" {
		return fmt.Errorf("Cannot attach interface without network name")
	}

	var networkSource kubevirtv1.NetworkSource
	switch net.NetworkType {
	case networkTypeGenie:
		networkSource = kubevirtv1.NetworkSource{
			Genie: &kubevirtv1.GenieNetwork{
				NetworkName: net.NetworkRef,
			},
		}
	case networkTypeMultus:
		networkSource = kubevirtv1.NetworkSource{
			Multus: &kubevirtv1.MultusNetwork{
				NetworkName: net.NetworkRef,
			},
		}
	case networkTypePod:
		networkSource = kubevirtv1.NetworkSource{
			Pod: &kubevirtv1.PodNetwork{},
		}
	default:
		return fmt.Errorf("Unsupported network type '%s'", net.NetworkType)
	}

	vmi.Spec.Domain.Devices.Interfaces = append(vmi.Spec.Domain.Devices.Interfaces, kubevirtv1.Interface{
		Name: net.Name,
		InterfaceBindingMethod: kubevirtv1.InterfaceBindingMethod{
			Bridge: &kubevirtv1.InterfaceBridge{},
		},
	})
	vmi.Spec.Networks = append(vmi.Spec.Networks, kubevirtv1.Network{
		Name:          net.Name,
		NetworkSource: networkSource,
	})

	return nil
}

// Delete method is used to delete an KubeVirt machine
func (d *KubeVirtDriver) Delete() error {
	kubevirt, namespace, err := d.createKubevirtClient()
	if err != nil {
		return fmt.Errorf("Failed to create KubeVirt client: %v", err)
	}

	machineName := d.decodeMachineID(d.MachineID)

	// Set delete propagation to ensure that userdata secret gets deleted after the last
	// VMI disappears from the cluster
	deletePropagation := metav1.DeletePropagationBackground
	deleteOptions := &metav1.DeleteOptions{
		PropagationPolicy: &deletePropagation,
	}

	if err := kubevirt.VirtualMachineInstance(namespace).Delete(machineName, deleteOptions); err != nil {
		if errors.IsNotFound(err) {
			glog.V(3).Infof("No VM matching the machine-ID found on the provider %q", d.MachineID)
			return nil
		}
		return fmt.Errorf("Failed to delete machine %s: %v", d.MachineID, err)
	}

	glog.V(3).Infof("Deleted machine with ID: %s", d.MachineID)
	return nil
}

// GetExisting method is used to get machineID for existing KubeVirt machine
func (d *KubeVirtDriver) GetExisting() (string, error) {
	return d.MachineID, nil
}

// GetVMs returns a VM matching the machineID
// If machineID is an empty string then it returns all matching instances
func (d *KubeVirtDriver) GetVMs(machineID string) (VMs, error) {
	vms := make(map[string]string)
	kubevirt, namespace, err := d.createKubevirtClient()
	if err != nil {
		return vms, fmt.Errorf("Failed to create KubeVirt client: %v", err)
	}
	vmis, err := d.listVMIs(kubevirt, namespace)
	if err != nil {
		return vms, fmt.Errorf("Failed to list machines: %v", err)
	}
	for _, vmi := range vmis {
		mID := d.encodeMachineID(vmi.ObjectMeta.Name)
		if machineID == "" {
			vms[mID] = vmi.ObjectMeta.Name
		} else if mID == machineID {
			vms[mID] = vmi.ObjectMeta.Name
			glog.V(3).Infof("Found machine with name: %q", vmi.ObjectMeta.Name)
			break
		}
	}
	return vms, nil
}

func (d *KubeVirtDriver) listVMIs(kubevirt kubecli.KubevirtClient, namespace string) ([]kubevirtv1.VirtualMachineInstance, error) {
	// Build label selectors to list all available machines
	labelSelectorOps := make([]string, 0)
	for k, v := range d.KubeVirtMachineClass.Spec.Tags {
		labelSelectorOps = append(labelSelectorOps, fmt.Sprintf("%s=%s", k, v))
	}
	labelSelector := strings.Join(labelSelectorOps, ",")

	vmis, err := kubevirt.VirtualMachineInstance(namespace).List(&metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return nil, err
	}
	return vmis.Items, nil
}

func (d *KubeVirtDriver) encodeMachineID(machineName string) string {
	return fmt.Sprintf("kubevirt:///%s", machineName)
}

func (d *KubeVirtDriver) decodeMachineID(id string) string {
	splitProviderID := strings.Split(id, "/")
	return splitProviderID[len(splitProviderID)-1]
}

func (d *KubeVirtDriver) ensureUserDataSecret(kubevirt kubecli.KubevirtClient, namespace string) (*corev1.Secret, error) {
	secretName := d.KubeVirtMachineClass.ObjectMeta.Name
	userdata := []byte(d.UserData)
	expectedSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels:    d.KubeVirtMachineClass.Spec.Tags,
		},
		Data: map[string][]byte{
			"userdata": userdata,
		},
	}

	secret, secFound, err := d.getUserDataSecret(kubevirt, secretName, namespace)
	if err != nil {
		return &corev1.Secret{}, err
	}
	if secFound {
		// Secret found -> Update if required
		secUserdata, ok := secret.Data["userdata"]
		if !ok || !bytes.Equal(secUserdata, userdata) {
			secret, err = kubevirt.CoreV1().Secrets(namespace).Update(&expectedSecret)
			if err != nil {
				return &corev1.Secret{}, err
			}
			glog.V(3).Infof("Updated user data secret %s", secretName)
		}
		return secret, nil
	}
	// Secret not found -> create it
	secret, err = kubevirt.CoreV1().Secrets(namespace).Create(&expectedSecret)
	if err != nil {
		return &corev1.Secret{}, err
	}
	glog.V(3).Infof("Created user data secret %s", secretName)
	return secret, nil
}

func (d *KubeVirtDriver) getUserDataSecret(kubevirt kubecli.KubevirtClient, name, namespace string) (*corev1.Secret, bool, error) {
	secret, err := kubevirt.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return secret, true, nil
}

func (d *KubeVirtDriver) createKubevirtClient() (kubecli.KubevirtClient, string, error) {
	kubeconfig, ok := d.CloudConfig.Data[v1alpha1.KubeVirtKubeConfig]
	if !ok {
		return nil, "", fmt.Errorf("Missing %s in secret", v1alpha1.KubeVirtKubeConfig)
	}
	namespace, ok := d.CloudConfig.Data[v1alpha1.KubeVirtNamespace]
	if !ok {
		return nil, "", fmt.Errorf("Missing %s in secret", v1alpha1.KubeVirtNamespace)
	}

	clientConfig, err := clientcmd.NewClientConfigFromBytes(kubeconfig)
	if err != nil {
		return nil, "", err
	}
	c, err := kubecli.GetKubevirtClientFromClientConfig(clientConfig)
	if err != nil {
		return nil, "", err
	}
	return c, string(namespace), nil
}
