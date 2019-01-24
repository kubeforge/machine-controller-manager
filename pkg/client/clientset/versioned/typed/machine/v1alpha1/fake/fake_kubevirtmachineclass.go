// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1alpha1 "github.com/gardener/machine-controller-manager/pkg/apis/machine/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeKubeVirtMachineClasses implements KubeVirtMachineClassInterface
type FakeKubeVirtMachineClasses struct {
	Fake *FakeMachineV1alpha1
	ns   string
}

var kubevirtmachineclassesResource = schema.GroupVersionResource{Group: "machine.sapcloud.io", Version: "v1alpha1", Resource: "kubevirtmachineclasses"}

var kubevirtmachineclassesKind = schema.GroupVersionKind{Group: "machine.sapcloud.io", Version: "v1alpha1", Kind: "KubeVirtMachineClass"}

// Get takes name of the kubeVirtMachineClass, and returns the corresponding kubeVirtMachineClass object, and an error if there is any.
func (c *FakeKubeVirtMachineClasses) Get(name string, options v1.GetOptions) (result *v1alpha1.KubeVirtMachineClass, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(kubevirtmachineclassesResource, c.ns, name), &v1alpha1.KubeVirtMachineClass{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.KubeVirtMachineClass), err
}

// List takes label and field selectors, and returns the list of KubeVirtMachineClasses that match those selectors.
func (c *FakeKubeVirtMachineClasses) List(opts v1.ListOptions) (result *v1alpha1.KubeVirtMachineClassList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(kubevirtmachineclassesResource, kubevirtmachineclassesKind, c.ns, opts), &v1alpha1.KubeVirtMachineClassList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.KubeVirtMachineClassList{ListMeta: obj.(*v1alpha1.KubeVirtMachineClassList).ListMeta}
	for _, item := range obj.(*v1alpha1.KubeVirtMachineClassList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested kubeVirtMachineClasses.
func (c *FakeKubeVirtMachineClasses) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(kubevirtmachineclassesResource, c.ns, opts))

}

// Create takes the representation of a kubeVirtMachineClass and creates it.  Returns the server's representation of the kubeVirtMachineClass, and an error, if there is any.
func (c *FakeKubeVirtMachineClasses) Create(kubeVirtMachineClass *v1alpha1.KubeVirtMachineClass) (result *v1alpha1.KubeVirtMachineClass, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(kubevirtmachineclassesResource, c.ns, kubeVirtMachineClass), &v1alpha1.KubeVirtMachineClass{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.KubeVirtMachineClass), err
}

// Update takes the representation of a kubeVirtMachineClass and updates it. Returns the server's representation of the kubeVirtMachineClass, and an error, if there is any.
func (c *FakeKubeVirtMachineClasses) Update(kubeVirtMachineClass *v1alpha1.KubeVirtMachineClass) (result *v1alpha1.KubeVirtMachineClass, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(kubevirtmachineclassesResource, c.ns, kubeVirtMachineClass), &v1alpha1.KubeVirtMachineClass{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.KubeVirtMachineClass), err
}

// Delete takes name of the kubeVirtMachineClass and deletes it. Returns an error if one occurs.
func (c *FakeKubeVirtMachineClasses) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(kubevirtmachineclassesResource, c.ns, name), &v1alpha1.KubeVirtMachineClass{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeKubeVirtMachineClasses) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(kubevirtmachineclassesResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &v1alpha1.KubeVirtMachineClassList{})
	return err
}

// Patch applies the patch and returns the patched kubeVirtMachineClass.
func (c *FakeKubeVirtMachineClasses) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.KubeVirtMachineClass, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(kubevirtmachineclassesResource, c.ns, name, data, subresources...), &v1alpha1.KubeVirtMachineClass{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.KubeVirtMachineClass), err
}
