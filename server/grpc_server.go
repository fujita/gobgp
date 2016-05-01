// Copyright (C) 2014,2015 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet/bgp"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"net"
	"strings"
)

const (
	_ = iota
	REQ_GLOBAL_CONFIG
	REQ_START_SERVER
	REQ_STOP_SERVER
	REQ_NEIGHBOR
	REQ_NEIGHBORS
	REQ_ADJ_RIB_IN
	REQ_ADJ_RIB_OUT
	REQ_LOCAL_RIB
	REQ_NEIGHBOR_SHUTDOWN
	REQ_NEIGHBOR_RESET
	REQ_NEIGHBOR_SOFT_RESET
	REQ_NEIGHBOR_SOFT_RESET_IN
	REQ_NEIGHBOR_SOFT_RESET_OUT
	REQ_NEIGHBOR_ENABLE
	REQ_NEIGHBOR_DISABLE
	REQ_ADD_NEIGHBOR
	REQ_DEL_NEIGHBOR
	// FIXME: we should merge
	REQ_GRPC_ADD_NEIGHBOR
	REQ_GRPC_DELETE_NEIGHBOR
	REQ_UPDATE_NEIGHBOR
	REQ_GLOBAL_RIB
	REQ_MONITOR_GLOBAL_BEST_CHANGED
	REQ_MONITOR_INCOMING
	REQ_MONITOR_NEIGHBOR_PEER_STATE
	REQ_MRT_GLOBAL_RIB
	REQ_MRT_LOCAL_RIB
	REQ_ENABLE_MRT
	REQ_DISABLE_MRT
	REQ_INJECT_MRT
	REQ_ADD_BMP
	REQ_DELETE_BMP
	REQ_VALIDATE_RIB
	// TODO: delete
	REQ_INITIALIZE_RPKI
	REQ_RPKI
	REQ_ADD_RPKI
	REQ_DELETE_RPKI
	REQ_ENABLE_RPKI
	REQ_DISABLE_RPKI
	REQ_RESET_RPKI
	REQ_SOFT_RESET_RPKI
	REQ_ROA
	REQ_ADD_VRF
	REQ_DELETE_VRF
	REQ_VRF
	REQ_VRFS
	REQ_ADD_PATH
	REQ_DELETE_PATH
	REQ_DEFINED_SET
	REQ_MOD_DEFINED_SET
	REQ_STATEMENT
	REQ_MOD_STATEMENT
	REQ_POLICY
	REQ_MOD_POLICY
	REQ_POLICY_ASSIGNMENT
	REQ_MOD_POLICY_ASSIGNMENT
	REQ_BMP_NEIGHBORS
	REQ_BMP_GLOBAL
	REQ_BMP_ADJ_IN
	REQ_DEFERRAL_TIMER_EXPIRED
	REQ_RELOAD_POLICY
)

type Server struct {
	grpcServer  *grpc.Server
	bgpServerCh chan *GrpcRequest
	hosts       string
}

func (s *Server) Serve() error {
	l := strings.Split(s.hosts, ",")
	for i, host := range l {
		lis, err := net.Listen("tcp", fmt.Sprintf(host))
		if err != nil {
			return fmt.Errorf("failed to listen: %v", err)
		}
		if i == len(l)-1 {
			s.grpcServer.Serve(lis)
		} else {
			go func() {
				s.grpcServer.Serve(lis)
			}()
		}
	}
	return nil
}

func (s *Server) GetNeighbor(ctx context.Context, arg *api.Arguments) (*api.Peer, error) {
	var rf bgp.RouteFamily
	req := NewGrpcRequest(REQ_NEIGHBOR, arg.Name, rf, nil)
	s.bgpServerCh <- req

	res := <-req.ResponseCh
	if err := res.Err(); err != nil {
		log.Debug(err.Error())
		return nil, err
	}

	return res.Data.(*api.Peer), nil
}

func handleMultipleResponses(req *GrpcRequest, f func(*GrpcResponse) error) error {
	for res := range req.ResponseCh {
		if err := res.Err(); err != nil {
			log.Debug(err.Error())
			req.EndCh <- struct{}{}
			return err
		}
		if err := f(res); err != nil {
			req.EndCh <- struct{}{}
			return err
		}
	}
	return nil
}

func (s *Server) GetNeighbors(_ *api.Arguments, stream api.GobgpApi_GetNeighborsServer) error {
	var rf bgp.RouteFamily
	req := NewGrpcRequest(REQ_NEIGHBORS, "", rf, nil)
	s.bgpServerCh <- req

	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.Peer))
	})
}

func (s *Server) GetRib(ctx context.Context, arg *api.Table) (*api.Table, error) {
	var reqType int
	switch arg.Type {
	case api.Resource_LOCAL:
		reqType = REQ_LOCAL_RIB
	case api.Resource_GLOBAL:
		reqType = REQ_GLOBAL_RIB
	case api.Resource_ADJ_IN:
		reqType = REQ_ADJ_RIB_IN
	case api.Resource_ADJ_OUT:
		reqType = REQ_ADJ_RIB_OUT
	case api.Resource_VRF:
		reqType = REQ_VRF
	default:
		return nil, fmt.Errorf("unsupported resource type: %v", arg.Type)
	}
	d, err := s.get(reqType, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.Table), nil
}

func (s *Server) MonitorBestChanged(arg *api.Arguments, stream api.GobgpApi_MonitorBestChangedServer) error {
	var reqType int
	switch arg.Resource {
	case api.Resource_GLOBAL:
		reqType = REQ_MONITOR_GLOBAL_BEST_CHANGED
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}

	req := NewGrpcRequest(reqType, "", bgp.RouteFamily(arg.Family), nil)
	s.bgpServerCh <- req

	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.Destination))
	})
}

func (s *Server) MonitorRib(arg *api.Table, stream api.GobgpApi_MonitorRibServer) error {
	switch arg.Type {
	case api.Resource_ADJ_IN:
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Type)
	}

	req := NewGrpcRequest(REQ_MONITOR_INCOMING, arg.Name, bgp.RouteFamily(arg.Family), arg)
	s.bgpServerCh <- req
	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.Destination))
	})
}

func (s *Server) MonitorPeerState(arg *api.Arguments, stream api.GobgpApi_MonitorPeerStateServer) error {
	var rf bgp.RouteFamily
	req := NewGrpcRequest(REQ_MONITOR_NEIGHBOR_PEER_STATE, arg.Name, rf, nil)
	s.bgpServerCh <- req

	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.Peer))
	})
}

func (s *Server) neighbor(reqType int, arg *api.Arguments) (*api.Error, error) {
	none := &api.Error{}
	req := NewGrpcRequest(reqType, arg.Name, bgp.RouteFamily(arg.Family), nil)
	s.bgpServerCh <- req

	res := <-req.ResponseCh
	if err := res.Err(); err != nil {
		log.Debug(err.Error())
		return nil, err
	}
	return none, nil
}

func (s *Server) Reset(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(REQ_NEIGHBOR_RESET, arg)
}

func (s *Server) SoftReset(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(REQ_NEIGHBOR_SOFT_RESET, arg)
}

func (s *Server) SoftResetIn(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(REQ_NEIGHBOR_SOFT_RESET_IN, arg)
}

func (s *Server) SoftResetOut(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(REQ_NEIGHBOR_SOFT_RESET_OUT, arg)
}

func (s *Server) Shutdown(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(REQ_NEIGHBOR_SHUTDOWN, arg)
}

func (s *Server) Enable(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(REQ_NEIGHBOR_ENABLE, arg)
}

func (s *Server) Disable(ctx context.Context, arg *api.Arguments) (*api.Error, error) {
	return s.neighbor(REQ_NEIGHBOR_DISABLE, arg)
}

func (s *Server) AddPath(ctx context.Context, arg *api.AddPathRequest) (*api.AddPathResponse, error) {
	d, err := s.get(REQ_ADD_PATH, arg)
	return d.(*api.AddPathResponse), err
}

func (s *Server) DeletePath(ctx context.Context, arg *api.DeletePathRequest) (*api.DeletePathResponse, error) {
	d, err := s.get(REQ_DELETE_PATH, arg)
	return d.(*api.DeletePathResponse), err
}

func (s *Server) EnableMrt(ctx context.Context, arg *api.EnableMrtRequest) (*api.EnableMrtResponse, error) {
	d, err := s.get(REQ_ENABLE_MRT, arg)
	return d.(*api.EnableMrtResponse), err
}

func (s *Server) DisableMrt(ctx context.Context, arg *api.DisableMrtRequest) (*api.DisableMrtResponse, error) {
	d, err := s.get(REQ_DISABLE_MRT, arg)
	return d.(*api.DisableMrtResponse), err
}

func (s *Server) InjectMrt(stream api.GobgpApi_InjectMrtServer) error {
	for {
		arg, err := stream.Recv()

		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if arg.Resource != api.Resource_GLOBAL && arg.Resource != api.Resource_VRF {
			return fmt.Errorf("unsupported resource: %s", arg.Resource)
		}

		req := NewGrpcRequest(REQ_INJECT_MRT, "", bgp.RouteFamily(0), arg)
		s.bgpServerCh <- req

		res := <-req.ResponseCh
		if err := res.Err(); err != nil {
			log.Debug(err.Error())
			return err
		}
	}
	return stream.SendAndClose(&api.InjectMrtResponse{})
}

func (s *Server) GetMrt(arg *api.MrtArguments, stream api.GobgpApi_GetMrtServer) error {
	var reqType int
	switch arg.Resource {
	case api.Resource_GLOBAL:
		reqType = REQ_MRT_GLOBAL_RIB
	case api.Resource_LOCAL:
		reqType = REQ_MRT_LOCAL_RIB
	default:
		return fmt.Errorf("unsupported resource type: %v", arg.Resource)
	}
	req := NewGrpcRequest(reqType, arg.NeighborAddress, bgp.RouteFamily(arg.Family), arg.Interval)
	s.bgpServerCh <- req
	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.MrtMessage))
	})
}

func (s *Server) AddBmp(ctx context.Context, arg *api.AddBmpRequest) (*api.AddBmpResponse, error) {
	d, err := s.get(REQ_ADD_BMP, arg)
	return d.(*api.AddBmpResponse), err
}

func (s *Server) DeleteBmp(ctx context.Context, arg *api.DeleteBmpRequest) (*api.DeleteBmpResponse, error) {
	d, err := s.get(REQ_DELETE_BMP, arg)
	return d.(*api.DeleteBmpResponse), err
}

func (s *Server) ValidateRib(ctx context.Context, arg *api.ValidateRibRequest) (*api.ValidateRibResponse, error) {
	d, err := s.get(REQ_VALIDATE_RIB, arg)
	return d.(*api.ValidateRibResponse), err
}

func (s *Server) AddRpki(ctx context.Context, arg *api.AddRpkiRequest) (*api.AddRpkiResponse, error) {
	d, err := s.get(REQ_ADD_RPKI, arg)
	return d.(*api.AddRpkiResponse), err
}

func (s *Server) DeleteRpki(ctx context.Context, arg *api.DeleteRpkiRequest) (*api.DeleteRpkiResponse, error) {
	d, err := s.get(REQ_DELETE_RPKI, arg)
	return d.(*api.DeleteRpkiResponse), err
}

func (s *Server) EnableRpki(ctx context.Context, arg *api.EnableRpkiRequest) (*api.EnableRpkiResponse, error) {
	d, err := s.get(REQ_ENABLE_RPKI, arg)
	return d.(*api.EnableRpkiResponse), err
}

func (s *Server) DisableRpki(ctx context.Context, arg *api.DisableRpkiRequest) (*api.DisableRpkiResponse, error) {
	d, err := s.get(REQ_DISABLE_RPKI, arg)
	return d.(*api.DisableRpkiResponse), err
}

func (s *Server) ResetRpki(ctx context.Context, arg *api.ResetRpkiRequest) (*api.ResetRpkiResponse, error) {
	d, err := s.get(REQ_RESET_RPKI, arg)
	return d.(*api.ResetRpkiResponse), err
}

func (s *Server) SoftResetRpki(ctx context.Context, arg *api.SoftResetRpkiRequest) (*api.SoftResetRpkiResponse, error) {
	d, err := s.get(REQ_SOFT_RESET_RPKI, arg)
	return d.(*api.SoftResetRpkiResponse), err
}

func (s *Server) GetRPKI(arg *api.Arguments, stream api.GobgpApi_GetRPKIServer) error {
	req := NewGrpcRequest(REQ_RPKI, "", bgp.RouteFamily(arg.Family), nil)
	s.bgpServerCh <- req

	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.RPKI))
	})
}

func (s *Server) GetROA(arg *api.Arguments, stream api.GobgpApi_GetROAServer) error {
	req := NewGrpcRequest(REQ_ROA, arg.Name, bgp.RouteFamily(arg.Family), nil)
	s.bgpServerCh <- req

	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.ROA))
	})
}

func (s *Server) GetVrfs(arg *api.Arguments, stream api.GobgpApi_GetVrfsServer) error {
	req := NewGrpcRequest(REQ_VRFS, "", bgp.RouteFamily(0), nil)
	s.bgpServerCh <- req

	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.Vrf))
	})
}

func (s *Server) get(typ int, d interface{}) (interface{}, error) {
	req := NewGrpcRequest(typ, "", bgp.RouteFamily(0), d)
	s.bgpServerCh <- req
	res := <-req.ResponseCh
	if err := res.Err(); err != nil {
		return nil, err
	}
	return res.Data, nil
}

func (s *Server) mod(typ int, d interface{}) (*api.Error, error) {
	none := &api.Error{}
	req := NewGrpcRequest(typ, "", bgp.RouteFamily(0), d)
	s.bgpServerCh <- req
	res := <-req.ResponseCh
	if err := res.Err(); err != nil {
		return none, err
	}
	return none, nil
}

func (s *Server) AddVrf(ctx context.Context, arg *api.AddVrfRequest) (*api.AddVrfResponse, error) {
	d, err := s.get(REQ_ADD_VRF, arg)
	return d.(*api.AddVrfResponse), err
}

func (s *Server) DeleteVrf(ctx context.Context, arg *api.DeleteVrfRequest) (*api.DeleteVrfResponse, error) {
	d, err := s.get(REQ_DELETE_VRF, arg)
	return d.(*api.DeleteVrfResponse), err
}

func (s *Server) AddNeighbor(ctx context.Context, arg *api.AddNeighborRequest) (*api.AddNeighborResponse, error) {
	d, err := s.get(REQ_GRPC_ADD_NEIGHBOR, arg)
	return d.(*api.AddNeighborResponse), err
}

func (s *Server) DeleteNeighbor(ctx context.Context, arg *api.DeleteNeighborRequest) (*api.DeleteNeighborResponse, error) {
	d, err := s.get(REQ_GRPC_DELETE_NEIGHBOR, arg)
	return d.(*api.DeleteNeighborResponse), err
}

func (s *Server) GetDefinedSet(ctx context.Context, arg *api.DefinedSet) (*api.DefinedSet, error) {
	d, err := s.get(REQ_DEFINED_SET, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.DefinedSet), nil
}

func (s *Server) GetDefinedSets(arg *api.DefinedSet, stream api.GobgpApi_GetDefinedSetsServer) error {
	req := NewGrpcRequest(REQ_DEFINED_SET, "", bgp.RouteFamily(0), arg)
	s.bgpServerCh <- req
	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.DefinedSet))
	})
}

func (s *Server) ModDefinedSet(ctx context.Context, arg *api.ModDefinedSetArguments) (*api.Error, error) {
	return s.mod(REQ_MOD_DEFINED_SET, arg)
}

func (s *Server) GetStatement(ctx context.Context, arg *api.Statement) (*api.Statement, error) {
	d, err := s.get(REQ_STATEMENT, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.Statement), nil
}

func (s *Server) GetStatements(arg *api.Statement, stream api.GobgpApi_GetStatementsServer) error {
	req := NewGrpcRequest(REQ_STATEMENT, "", bgp.RouteFamily(0), arg)
	s.bgpServerCh <- req
	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.Statement))
	})
}

func (s *Server) ModStatement(ctx context.Context, arg *api.ModStatementArguments) (*api.Error, error) {
	return s.mod(REQ_MOD_STATEMENT, arg)
}

func (s *Server) GetPolicy(ctx context.Context, arg *api.Policy) (*api.Policy, error) {
	d, err := s.get(REQ_POLICY, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.Policy), nil
}

func (s *Server) GetPolicies(arg *api.Policy, stream api.GobgpApi_GetPoliciesServer) error {
	req := NewGrpcRequest(REQ_POLICY, "", bgp.RouteFamily(0), arg)
	s.bgpServerCh <- req
	return handleMultipleResponses(req, func(res *GrpcResponse) error {
		return stream.Send(res.Data.(*api.Policy))
	})
}

func (s *Server) ModPolicy(ctx context.Context, arg *api.ModPolicyArguments) (*api.Error, error) {
	return s.mod(REQ_MOD_POLICY, arg)
}

func (s *Server) GetPolicyAssignment(ctx context.Context, arg *api.PolicyAssignment) (*api.PolicyAssignment, error) {
	d, err := s.get(REQ_POLICY_ASSIGNMENT, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.PolicyAssignment), nil
}

func (s *Server) ModPolicyAssignment(ctx context.Context, arg *api.ModPolicyAssignmentArguments) (*api.Error, error) {
	return s.mod(REQ_MOD_POLICY_ASSIGNMENT, arg)
}

func (s *Server) GetGlobalConfig(ctx context.Context, arg *api.Arguments) (*api.Global, error) {
	d, err := s.get(REQ_GLOBAL_CONFIG, arg)
	if err != nil {
		return nil, err
	}
	return d.(*api.Global), nil
}

func (s *Server) StartServer(ctx context.Context, arg *api.StartServerRequest) (*api.StartServerResponse, error) {
	d, err := s.get(REQ_START_SERVER, arg)
	return d.(*api.StartServerResponse), err
}

func (s *Server) StopServer(ctx context.Context, arg *api.StopServerRequest) (*api.StopServerResponse, error) {
	d, err := s.get(REQ_STOP_SERVER, arg)
	return d.(*api.StopServerResponse), err
}

type GrpcRequest struct {
	RequestType int
	Name        string
	RouteFamily bgp.RouteFamily
	ResponseCh  chan *GrpcResponse
	EndCh       chan struct{}
	Err         error
	Data        interface{}
}

func NewGrpcRequest(reqType int, name string, rf bgp.RouteFamily, d interface{}) *GrpcRequest {
	r := &GrpcRequest{
		RequestType: reqType,
		RouteFamily: rf,
		Name:        name,
		ResponseCh:  make(chan *GrpcResponse, 8),
		EndCh:       make(chan struct{}, 1),
		Data:        d,
	}
	return r
}

type GrpcResponse struct {
	ResponseErr error
	Data        interface{}
}

func (r *GrpcResponse) Err() error {
	return r.ResponseErr
}

func NewGrpcServer(hosts string, bgpServerCh chan *GrpcRequest) *Server {
	grpc.EnableTracing = false
	grpcServer := grpc.NewServer()
	server := &Server{
		grpcServer:  grpcServer,
		bgpServerCh: bgpServerCh,
		hosts:       hosts,
	}
	api.RegisterGobgpApiServer(grpcServer, server)
	return server
}
