// +build !ignore_autogenerated

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

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DataVolume) DeepCopyInto(out *DataVolume) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DataVolume.
func (in *DataVolume) DeepCopy() *DataVolume {
	if in == nil {
		return nil
	}
	out := new(DataVolume)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DataVolume) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DataVolumeBlankImage) DeepCopyInto(out *DataVolumeBlankImage) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DataVolumeBlankImage.
func (in *DataVolumeBlankImage) DeepCopy() *DataVolumeBlankImage {
	if in == nil {
		return nil
	}
	out := new(DataVolumeBlankImage)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DataVolumeList) DeepCopyInto(out *DataVolumeList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]DataVolume, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DataVolumeList.
func (in *DataVolumeList) DeepCopy() *DataVolumeList {
	if in == nil {
		return nil
	}
	out := new(DataVolumeList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DataVolumeList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DataVolumeSource) DeepCopyInto(out *DataVolumeSource) {
	*out = *in
	if in.HTTP != nil {
		in, out := &in.HTTP, &out.HTTP
		*out = new(DataVolumeSourceHTTP)
		**out = **in
	}
	if in.S3 != nil {
		in, out := &in.S3, &out.S3
		*out = new(DataVolumeSourceS3)
		**out = **in
	}
	if in.PVC != nil {
		in, out := &in.PVC, &out.PVC
		*out = new(DataVolumeSourcePVC)
		**out = **in
	}
	if in.Upload != nil {
		in, out := &in.Upload, &out.Upload
		*out = new(DataVolumeSourceUpload)
		**out = **in
	}
	if in.Blank != nil {
		in, out := &in.Blank, &out.Blank
		*out = new(DataVolumeBlankImage)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DataVolumeSource.
func (in *DataVolumeSource) DeepCopy() *DataVolumeSource {
	if in == nil {
		return nil
	}
	out := new(DataVolumeSource)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DataVolumeSourceHTTP) DeepCopyInto(out *DataVolumeSourceHTTP) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DataVolumeSourceHTTP.
func (in *DataVolumeSourceHTTP) DeepCopy() *DataVolumeSourceHTTP {
	if in == nil {
		return nil
	}
	out := new(DataVolumeSourceHTTP)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DataVolumeSourcePVC) DeepCopyInto(out *DataVolumeSourcePVC) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DataVolumeSourcePVC.
func (in *DataVolumeSourcePVC) DeepCopy() *DataVolumeSourcePVC {
	if in == nil {
		return nil
	}
	out := new(DataVolumeSourcePVC)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DataVolumeSourceS3) DeepCopyInto(out *DataVolumeSourceS3) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DataVolumeSourceS3.
func (in *DataVolumeSourceS3) DeepCopy() *DataVolumeSourceS3 {
	if in == nil {
		return nil
	}
	out := new(DataVolumeSourceS3)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DataVolumeSourceUpload) DeepCopyInto(out *DataVolumeSourceUpload) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DataVolumeSourceUpload.
func (in *DataVolumeSourceUpload) DeepCopy() *DataVolumeSourceUpload {
	if in == nil {
		return nil
	}
	out := new(DataVolumeSourceUpload)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DataVolumeSpec) DeepCopyInto(out *DataVolumeSpec) {
	*out = *in
	in.Source.DeepCopyInto(&out.Source)
	if in.PVC != nil {
		in, out := &in.PVC, &out.PVC
		*out = new(v1.PersistentVolumeClaimSpec)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DataVolumeSpec.
func (in *DataVolumeSpec) DeepCopy() *DataVolumeSpec {
	if in == nil {
		return nil
	}
	out := new(DataVolumeSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DataVolumeStatus) DeepCopyInto(out *DataVolumeStatus) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DataVolumeStatus.
func (in *DataVolumeStatus) DeepCopy() *DataVolumeStatus {
	if in == nil {
		return nil
	}
	out := new(DataVolumeStatus)
	in.DeepCopyInto(out)
	return out
}