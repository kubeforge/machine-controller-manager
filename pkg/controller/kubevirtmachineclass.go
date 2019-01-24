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

// Package controller is used to provide the core functionalities of machine-controller-manager
package controller

import (
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	"github.com/golang/glog"

	"github.com/gardener/machine-controller-manager/pkg/apis/machine"
	"github.com/gardener/machine-controller-manager/pkg/apis/machine/v1alpha1"
	"github.com/gardener/machine-controller-manager/pkg/apis/machine/validation"
)

// KubeVirtMachineClassKind is used to identify the machineClassKind as KubeVirt
const KubeVirtMachineClassKind = "KubeVirtMachineClass"

func (c *controller) machineDeploymentToKubeVirtMachineClassDelete(obj interface{}) {
	machineDeployment, ok := obj.(*v1alpha1.MachineDeployment)
	if machineDeployment == nil || !ok {
		return
	}
	if machineDeployment.Spec.Template.Spec.Class.Kind == KubeVirtMachineClassKind {
		c.kubeVirtMachineClassQueue.Add(machineDeployment.Spec.Template.Spec.Class.Name)
	}
}

func (c *controller) machineSetToKubeVirtMachineClassDelete(obj interface{}) {
	machineSet, ok := obj.(*v1alpha1.MachineSet)
	if machineSet == nil || !ok {
		return
	}
	if machineSet.Spec.Template.Spec.Class.Kind == KubeVirtMachineClassKind {
		c.kubeVirtMachineClassQueue.Add(machineSet.Spec.Template.Spec.Class.Name)
	}
}

func (c *controller) machineToKubeVirtMachineClassDelete(obj interface{}) {
	machine, ok := obj.(*v1alpha1.Machine)
	if machine == nil || !ok {
		return
	}
	if machine.Spec.Class.Kind == KubeVirtMachineClassKind {
		c.kubeVirtMachineClassQueue.Add(machine.Spec.Class.Name)
	}
}

func (c *controller) kubeVirtMachineClassAdd(obj interface{}) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		glog.Errorf("Couldn't get key for object %+v: %v", obj, err)
		return
	}
	c.kubeVirtMachineClassQueue.Add(key)
}

func (c *controller) kubeVirtMachineClassUpdate(oldObj, newObj interface{}) {
	old, ok := oldObj.(*v1alpha1.KubeVirtMachineClass)
	if old == nil || !ok {
		return
	}
	new, ok := newObj.(*v1alpha1.KubeVirtMachineClass)
	if new == nil || !ok {
		return
	}

	c.kubeVirtMachineClassAdd(newObj)
}

// reconcileClusterKubeVirtMachineClassKey reconciles an KubeVirtMachineClass due to controller resync
// or an event on the kubeVirtMachineClass.
func (c *controller) reconcileClusterKubeVirtMachineClassKey(key string) error {
	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	class, err := c.kubeVirtMachineClassLister.KubeVirtMachineClasses(c.namespace).Get(name)
	if errors.IsNotFound(err) {
		glog.V(4).Infof("%s %q: Not doing work because it has been deleted", KubeVirtMachineClassKind, key)
		return nil
	}
	if err != nil {
		glog.V(4).Infof("%s %q: Unable to retrieve object from store: %v", KubeVirtMachineClassKind, key, err)
		return err
	}

	return c.reconcileClusterKubeVirtMachineClass(class)
}

func (c *controller) reconcileClusterKubeVirtMachineClass(class *v1alpha1.KubeVirtMachineClass) error {
	internalClass := &machine.KubeVirtMachineClass{}
	err := c.internalExternalScheme.Convert(class, internalClass, nil)
	if err != nil {
		return err
	}

	// TODO this should be put in own API server
	validationerr := validation.ValidateKubeVirtMachineClass(internalClass)
	if validationerr.ToAggregate() != nil && len(validationerr.ToAggregate().Errors()) > 0 {
		glog.Errorf("Validation of %s failed %s", KubeVirtMachineClassKind, validationerr.ToAggregate().Error())
		return nil
	}

	// Manipulate finalizers
	if class.DeletionTimestamp == nil {
		c.addKubeVirtMachineClassFinalizers(class)
	}

	machines, err := c.findMachinesForClass(KubeVirtMachineClassKind, class.Name)
	if err != nil {
		return err
	}

	if class.DeletionTimestamp != nil {
		if finalizers := sets.NewString(class.Finalizers...); !finalizers.Has(DeleteFinalizerName) {
			return nil
		}

		machineDeployments, err := c.findMachineDeploymentsForClass(KubeVirtMachineClassKind, class.Name)
		if err != nil {
			return err
		}
		machineSets, err := c.findMachineSetsForClass(KubeVirtMachineClassKind, class.Name)
		if err != nil {
			return err
		}
		if len(machineDeployments) == 0 && len(machineSets) == 0 && len(machines) == 0 {
			c.deleteKubeVirtMachineClassFinalizers(class)
			return nil
		}

		glog.V(3).Infof("Cannot remove finalizer of %s because still Machine[s|Sets|Deployments] are referencing it", class.Name)
		return nil
	}

	for _, machine := range machines {
		c.addMachine(machine)
	}
	return nil
}

/*
	SECTION
	Manipulate Finalizers
*/

func (c *controller) addKubeVirtMachineClassFinalizers(class *v1alpha1.KubeVirtMachineClass) {
	clone := class.DeepCopy()

	if finalizers := sets.NewString(clone.Finalizers...); !finalizers.Has(DeleteFinalizerName) {
		finalizers.Insert(DeleteFinalizerName)
		c.updateKubeVirtMachineClassFinalizers(clone, finalizers.List())
	}
}

func (c *controller) deleteKubeVirtMachineClassFinalizers(class *v1alpha1.KubeVirtMachineClass) {
	clone := class.DeepCopy()

	if finalizers := sets.NewString(clone.Finalizers...); finalizers.Has(DeleteFinalizerName) {
		finalizers.Delete(DeleteFinalizerName)
		c.updateKubeVirtMachineClassFinalizers(clone, finalizers.List())
	}
}

func (c *controller) updateKubeVirtMachineClassFinalizers(class *v1alpha1.KubeVirtMachineClass, finalizers []string) {
	// Get the latest version of the class so that we can avoid conflicts
	class, err := c.controlMachineClient.KubeVirtMachineClasses(class.Namespace).Get(class.Name, metav1.GetOptions{})
	if err != nil {
		return
	}

	clone := class.DeepCopy()
	clone.Finalizers = finalizers
	_, err = c.controlMachineClient.KubeVirtMachineClasses(class.Namespace).Update(clone)
	if err != nil {
		// Keep retrying until update goes through
		glog.Warning("Updated failed, retrying")
		c.updateKubeVirtMachineClassFinalizers(class, finalizers)
	}
}
