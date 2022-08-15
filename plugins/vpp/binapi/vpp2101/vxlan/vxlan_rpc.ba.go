// Code generated by GoVPP's binapi-generator. DO NOT EDIT.

package vxlan

import (
	"context"
	"fmt"
	"io"

	api "go.fd.io/govpp/api"
	vpe "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2101/vpe"
)

// RPCService defines RPC service  vxlan.
type RPCService interface {
	SwInterfaceSetVxlanBypass(ctx context.Context, in *SwInterfaceSetVxlanBypass) (*SwInterfaceSetVxlanBypassReply, error)
	VxlanAddDelTunnel(ctx context.Context, in *VxlanAddDelTunnel) (*VxlanAddDelTunnelReply, error)
	VxlanOffloadRx(ctx context.Context, in *VxlanOffloadRx) (*VxlanOffloadRxReply, error)
	VxlanTunnelDump(ctx context.Context, in *VxlanTunnelDump) (RPCService_VxlanTunnelDumpClient, error)
}

type serviceClient struct {
	conn api.Connection
}

func NewServiceClient(conn api.Connection) RPCService {
	return &serviceClient{conn}
}

func (c *serviceClient) SwInterfaceSetVxlanBypass(ctx context.Context, in *SwInterfaceSetVxlanBypass) (*SwInterfaceSetVxlanBypassReply, error) {
	out := new(SwInterfaceSetVxlanBypassReply)
	err := c.conn.Invoke(ctx, in, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) VxlanAddDelTunnel(ctx context.Context, in *VxlanAddDelTunnel) (*VxlanAddDelTunnelReply, error) {
	out := new(VxlanAddDelTunnelReply)
	err := c.conn.Invoke(ctx, in, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) VxlanOffloadRx(ctx context.Context, in *VxlanOffloadRx) (*VxlanOffloadRxReply, error) {
	out := new(VxlanOffloadRxReply)
	err := c.conn.Invoke(ctx, in, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) VxlanTunnelDump(ctx context.Context, in *VxlanTunnelDump) (RPCService_VxlanTunnelDumpClient, error) {
	stream, err := c.conn.NewStream(ctx)
	if err != nil {
		return nil, err
	}
	x := &serviceClient_VxlanTunnelDumpClient{stream}
	if err := x.Stream.SendMsg(in); err != nil {
		return nil, err
	}
	if err = x.Stream.SendMsg(&vpe.ControlPing{}); err != nil {
		return nil, err
	}
	return x, nil
}

type RPCService_VxlanTunnelDumpClient interface {
	Recv() (*VxlanTunnelDetails, error)
	api.Stream
}

type serviceClient_VxlanTunnelDumpClient struct {
	api.Stream
}

func (c *serviceClient_VxlanTunnelDumpClient) Recv() (*VxlanTunnelDetails, error) {
	msg, err := c.Stream.RecvMsg()
	if err != nil {
		return nil, err
	}
	switch m := msg.(type) {
	case *VxlanTunnelDetails:
		return m, nil
	case *vpe.ControlPingReply:
		return nil, io.EOF
	default:
		return nil, fmt.Errorf("unexpected message: %T %v", m, m)
	}
}
