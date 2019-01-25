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
	"fmt"
	"strconv"
	"strings"

	v1alpha1 "github.com/gardener/machine-controller-manager/pkg/apis/machine/v1alpha1"
	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
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

	if d.UserData != "" {
		d.attachCloudInitDisk(instance)
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
	return d.MachineID, d.MachineName, nil

}

func (d *KubeVirtDriver) attachCloudInitDisk(vmi *kubevirtv1.VirtualMachineInstance) {
	vmi.Spec.Domain.Devices.Disks = append(vmi.Spec.Domain.Devices.Disks, kubevirtv1.Disk{
		Name: cloudInitDiskName,
	})
	vmi.Spec.Volumes = append(vmi.Spec.Volumes, kubevirtv1.Volume{
		Name: cloudInitDiskName,
		VolumeSource: kubevirtv1.VolumeSource{
			CloudInitNoCloud: &kubevirtv1.CloudInitNoCloudSource{
				UserData: d.UserData,
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
			Genie: &kubevirtv1.CniNetwork{
				NetworkName: net.NetworkRef,
			},
		}
	case networkTypeMultus:
		networkSource = kubevirtv1.NetworkSource{
			Multus: &kubevirtv1.CniNetwork{
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
	res, err := d.GetVMs(d.MachineID)
	if err != nil {
		return err
	} else if len(res) == 0 {
		// No running instance exists with the given machine-ID
		glog.V(2).Infof("No VM matching the machine-ID found on the provider %q", d.MachineID)
		return nil
	}

	machineName := d.decodeMachineID(d.MachineID)
	kubevirt, namespace, err := d.createKubevirtClient()
	if err != nil {
		return fmt.Errorf("Failed to create KubeVirt client: %v", err)
	}

	if err := kubevirt.VirtualMachineInstance(namespace).Delete(machineName, &metav1.DeleteOptions{}); err != nil {
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

	// Build label selectors to list all available machines
	labelSelectorOps := make([]string, 0)
	for k, v := range d.KubeVirtMachineClass.Spec.Tags {
		labelSelectorOps = append(labelSelectorOps, fmt.Sprintf("%s=%s", k, v))
	}
	labelSelector := strings.Join(labelSelectorOps, ",")

	vmis, err := d.listVMIs(labelSelector)
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

func (d *KubeVirtDriver) listVMIs(labelSelector string) ([]kubevirtv1.VirtualMachineInstance, error) {
	kubevirt, namespace, err := d.createKubevirtClient()
	if err != nil {
		return nil, fmt.Errorf("Failed to create KubeVirt client: %v", err)
	}
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

func (d *KubeVirtDriver) createKubevirtClient() (kubecli.KubevirtClient, string, error) {
	clusterName, ok := d.CloudConfig.Data[v1alpha1.KubeVirtClusterName]
	if !ok {
		return nil, "", fmt.Errorf("Missing %s in secret", v1alpha1.KubeVirtClusterName)
	}

	clusterServer, ok := d.CloudConfig.Data[v1alpha1.KubeVirtClusterServer]
	if !ok {
		return nil, "", fmt.Errorf("Missing %s in secret", v1alpha1.KubeVirtClusterServer)
	}

	clusterCertificateAuthorityData, ok := d.CloudConfig.Data[v1alpha1.KubeVirtClusterCertificateAuthorityData]
	if !ok {
		return nil, "", fmt.Errorf("Missing %s in secret", v1alpha1.KubeVirtClusterCertificateAuthorityData)
	}

	authInfoName, ok := d.CloudConfig.Data[v1alpha1.KubeVirtAuthInfoName]
	if !ok {
		return nil, "", fmt.Errorf("Missing %s in secret", v1alpha1.KubeVirtAuthInfoName)
	}

	authInfoClientCertificateData, ok := d.CloudConfig.Data[v1alpha1.KubeVirtAuthInfoClientCertificateData]
	if !ok {
		return nil, "", fmt.Errorf("Missing %s in secret", v1alpha1.KubeVirtAuthInfoClientCertificateData)
	}

	authInfoClientKeyData, ok := d.CloudConfig.Data[v1alpha1.KubeVirtAuthInfoClientKeyData]
	if !ok {
		return nil, "", fmt.Errorf("Missing %s in secret", v1alpha1.KubeVirtAuthInfoClientKeyData)
	}

	contextName, ok := d.CloudConfig.Data[v1alpha1.KubeVirtContextName]
	if !ok {
		return nil, "", fmt.Errorf("Missing %s in secret", v1alpha1.KubeVirtContextName)
	}

	contextNamespace, ok := d.CloudConfig.Data[v1alpha1.KubeVirtContextNamespace]
	if !ok {
		return nil, "", fmt.Errorf("Missing %s in secret", v1alpha1.KubeVirtContextNamespace)
	}

	config := clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			string(clusterName): {
				Server:                   string(clusterServer),
				CertificateAuthorityData: clusterCertificateAuthorityData,
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			string(authInfoName): {
				ClientCertificateData: authInfoClientCertificateData,
				ClientKeyData:         authInfoClientKeyData,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			string(contextName): {
				Cluster:   string(clusterName),
				AuthInfo:  string(authInfoName),
				Namespace: string(contextNamespace),
			},
		},
		CurrentContext: string(contextName),
	}
	clientConfig := clientcmd.NewDefaultClientConfig(config, &clientcmd.ConfigOverrides{})
	kubevirtClient, err := kubecli.GetKubevirtClientFromClientConfig(clientConfig)
	if err != nil {
		return nil, "", err
	}
	return kubevirtClient, string(contextNamespace), nil
}
