/*
Copyright 2017 The Kubernetes Authors.

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

package driver

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	v1alpha1 "github.com/gardener/machine-controller-manager/pkg/apis/machine/v1alpha1"
	cmipb "github.com/gardener/machine-spec/lib/go/cmi"
	corev1 "k8s.io/api/core/v1"

	"github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type cmiClient interface {
	CreateMachine(ctx context.Context) (string, string, error)
	DeleteMachine(ctx context.Context) error
	ListMachines(ctx context.Context) (string, error)
}

type CmiDriverClient struct {
	DriverName           string
	MachineClientCreator machineClientCreator
	MachineClass         *v1alpha1.AWSMachineClass
	CloudConfig          *corev1.Secret
	UserData             string
	MachineID            string
	MachineName          string
}

type machineClientCreator func(driverName string) (
	machineClient cmipb.MachineClient,
	closer io.Closer,
	err error,
)

type VMs map[string]string

func newMachineClient(driverName string) (machineClient cmipb.MachineClient, closer io.Closer, err error) {
	var conn *grpc.ClientConn
	conn, err = newGrpcConn(driverName)
	if err != nil {
		return nil, nil, err
	}

	machineClient = cmipb.NewMachineClient(conn)
	return machineClient, conn, nil
}

// NewCmiDriverClient
func NewCmiDriverClient(machineID string, driverName string, secret *corev1.Secret, machineClass interface{}, machineName string) *CmiDriverClient {
	c := &CmiDriverClient{
		DriverName:           driverName,
		MachineClientCreator: newMachineClient,
		MachineClass:         machineClass.(*v1alpha1.AWSMachineClass),
		CloudConfig:          secret,
		UserData:             string(secret.Data["userData"]),
		MachineID:            machineID,
		MachineName:          machineName,
	}
	return c
}

func (c *CmiDriverClient) CreateMachine() (string, string, error) {
	glog.V(2).Info("Calling CreateMachine rpc ........", c)

	machineClient, closer, err := c.MachineClientCreator(c.DriverName)
	if err != nil {
		return "", "", err
	}
	defer closer.Close()

	req := &cmipb.CreateMachineRequest{
		Providerconfig: "MachineClass.ProviderConfig here",
	}
	ctx := context.Background()
	resp, err := machineClient.CreateMachine(ctx, req)
	if err != nil {
		return "", "", err
	}
	fmt.Println(resp)

	return resp.ProviderID, resp.Name, err
}

func (c *CmiDriverClient) DeleteMachine() error {
	glog.V(4).Info("Calling DeleteMachine rpc")

	machineClient, closer, err := c.MachineClientCreator(c.DriverName)
	if err != nil {
		return err
	}
	defer closer.Close()

	req := &cmipb.DeleteMachineRequest{
		Name: c.MachineName,
	}
	ctx := context.Background()
	resp, err := machineClient.DeleteMachine(ctx, req)
	if err != nil {
		return err
	}
	fmt.Println(resp, err)
	return err
}

func (c *CmiDriverClient) ListMachine() ([]string, error) {
	glog.V(4).Info("Calling ListMachine rpc")
	return nil, status.Error(codes.Unimplemented, "")
}

func (c *CmiDriverClient) GetVMs(machineID string) (map[string]string, error) {
	glog.V(4).Info("Calling GetVMSs call")
	return nil, nil
}

func (c *CmiDriverClient) GetExisting() (string, error) {
	glog.V(4).Info("Calling GetExisting  rpc")
	return c.MachineID, nil
}

func newGrpcConn(driverName string) (*grpc.ClientConn, error) {
	if driverName == "" {
		return nil, fmt.Errorf("driver name is empty")
	}

	network := "tcp"
	addr := "127.0.0.1:8080"
	glog.V(4).Infof("creating new gRPC connection for [%s://%s]", network, addr)

	return grpc.Dial(
		addr,
		grpc.WithInsecure(),
		grpc.WithDialer(func(target string, timeout time.Duration) (net.Conn, error) {
			return net.Dial(network, target)
		}),
	)
}
