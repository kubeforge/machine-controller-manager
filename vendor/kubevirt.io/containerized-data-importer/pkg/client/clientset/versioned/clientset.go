/*
Copyright 2018 The CDI Authors.

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

// Code generated by client-gen. DO NOT EDIT.

package versioned

import (
	discovery "k8s.io/client-go/discovery"
	rest "k8s.io/client-go/rest"
	flowcontrol "k8s.io/client-go/util/flowcontrol"
	cdiv1alpha1 "kubevirt.io/containerized-data-importer/pkg/client/clientset/versioned/typed/datavolumecontroller/v1alpha1"
	uploadv1alpha1 "kubevirt.io/containerized-data-importer/pkg/client/clientset/versioned/typed/uploadcontroller/v1alpha1"
)

type Interface interface {
	Discovery() discovery.DiscoveryInterface
	CdiV1alpha1() cdiv1alpha1.CdiV1alpha1Interface
	// Deprecated: please explicitly pick a version if possible.
	Cdi() cdiv1alpha1.CdiV1alpha1Interface
	UploadV1alpha1() uploadv1alpha1.UploadV1alpha1Interface
	// Deprecated: please explicitly pick a version if possible.
	Upload() uploadv1alpha1.UploadV1alpha1Interface
}

// Clientset contains the clients for groups. Each group has exactly one
// version included in a Clientset.
type Clientset struct {
	*discovery.DiscoveryClient
	cdiV1alpha1    *cdiv1alpha1.CdiV1alpha1Client
	uploadV1alpha1 *uploadv1alpha1.UploadV1alpha1Client
}

// CdiV1alpha1 retrieves the CdiV1alpha1Client
func (c *Clientset) CdiV1alpha1() cdiv1alpha1.CdiV1alpha1Interface {
	return c.cdiV1alpha1
}

// Deprecated: Cdi retrieves the default version of CdiClient.
// Please explicitly pick a version.
func (c *Clientset) Cdi() cdiv1alpha1.CdiV1alpha1Interface {
	return c.cdiV1alpha1
}

// UploadV1alpha1 retrieves the UploadV1alpha1Client
func (c *Clientset) UploadV1alpha1() uploadv1alpha1.UploadV1alpha1Interface {
	return c.uploadV1alpha1
}

// Deprecated: Upload retrieves the default version of UploadClient.
// Please explicitly pick a version.
func (c *Clientset) Upload() uploadv1alpha1.UploadV1alpha1Interface {
	return c.uploadV1alpha1
}

// Discovery retrieves the DiscoveryClient
func (c *Clientset) Discovery() discovery.DiscoveryInterface {
	if c == nil {
		return nil
	}
	return c.DiscoveryClient
}

// NewForConfig creates a new Clientset for the given config.
func NewForConfig(c *rest.Config) (*Clientset, error) {
	configShallowCopy := *c
	if configShallowCopy.RateLimiter == nil && configShallowCopy.QPS > 0 {
		configShallowCopy.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(configShallowCopy.QPS, configShallowCopy.Burst)
	}
	var cs Clientset
	var err error
	cs.cdiV1alpha1, err = cdiv1alpha1.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	cs.uploadV1alpha1, err = uploadv1alpha1.NewForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}

	cs.DiscoveryClient, err = discovery.NewDiscoveryClientForConfig(&configShallowCopy)
	if err != nil {
		return nil, err
	}
	return &cs, nil
}

// NewForConfigOrDie creates a new Clientset for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *Clientset {
	var cs Clientset
	cs.cdiV1alpha1 = cdiv1alpha1.NewForConfigOrDie(c)
	cs.uploadV1alpha1 = uploadv1alpha1.NewForConfigOrDie(c)

	cs.DiscoveryClient = discovery.NewDiscoveryClientForConfigOrDie(c)
	return &cs
}

// New creates a new Clientset for the given RESTClient.
func New(c rest.Interface) *Clientset {
	var cs Clientset
	cs.cdiV1alpha1 = cdiv1alpha1.New(c)
	cs.uploadV1alpha1 = uploadv1alpha1.New(c)

	cs.DiscoveryClient = discovery.NewDiscoveryClient(c)
	return &cs
}
