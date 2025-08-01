package config

import (
	"context"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

// ReadConfigFile parses a config file into a BgpConfigSet which can be applied
// using InitialConfig and UpdateConfig.
func ReadConfigFile(configFile, configType string) (*oc.BgpConfigSet, error) {
	return oc.ReadConfigfile(configFile, configType)
}

// WatchConfigFile calls the callback function anytime an update to the
// config file is detected.
func WatchConfigFile(configFile, configType string, callBack func()) {
	oc.WatchConfigFile(configFile, configType, callBack)
}

func marshalRouteTargets(l []string) ([]*api.RouteTarget, error) {
	rtList := make([]*api.RouteTarget, 0, len(l))
	for _, rtString := range l {
		rt, err := bgp.ParseRouteTarget(rtString)
		if err != nil {
			return nil, err
		}
		a, err := apiutil.MarshalRT(rt)
		if err != nil {
			return nil, err
		}
		rtList = append(rtList, a)
	}
	return rtList, nil
}

func assignGlobalpolicy(ctx context.Context, bgpServer *server.BgpServer, a *oc.ApplyPolicyConfig) {
	toDefaultTable := func(r oc.DefaultPolicyType) table.RouteType {
		var def table.RouteType
		switch r {
		case oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE:
			def = table.ROUTE_TYPE_ACCEPT
		case oc.DEFAULT_POLICY_TYPE_REJECT_ROUTE:
			def = table.ROUTE_TYPE_REJECT
		}
		return def
	}
	toPolicies := func(r []string) []*table.Policy {
		p := make([]*table.Policy, 0, len(r))
		for _, n := range r {
			p = append(p, &table.Policy{
				Name: n,
			})
		}
		return p
	}

	def := toDefaultTable(a.DefaultImportPolicy)
	ps := toPolicies(a.ImportPolicyList)
	err := bgpServer.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
		Assignment: table.NewAPIPolicyAssignmentFromTableStruct(&table.PolicyAssignment{
			Name:     table.GLOBAL_RIB_NAME,
			Type:     table.POLICY_DIRECTION_IMPORT,
			Policies: ps,
			Default:  def,
		}),
	})
	if err != nil {
		bgpServer.Log().Fatal("failed to set policy assignment",
			log.Fields{
				log.FieldFacility: log.FacilityConfig,
				"Topic":           "config",
				"Direction":       table.POLICY_DIRECTION_IMPORT,
				"Error":           err,
			})
	}

	def = toDefaultTable(a.DefaultExportPolicy)
	ps = toPolicies(a.ExportPolicyList)
	err = bgpServer.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
		Assignment: table.NewAPIPolicyAssignmentFromTableStruct(&table.PolicyAssignment{
			Name:     table.GLOBAL_RIB_NAME,
			Type:     table.POLICY_DIRECTION_EXPORT,
			Policies: ps,
			Default:  def,
		}),
	})
	if err != nil {
		bgpServer.Log().Fatal("failed to set policy assignment",
			log.Fields{
				log.FieldFacility: log.FacilityConfig,
				"Topic":           "config",
				"Direction":       table.POLICY_DIRECTION_EXPORT,
				"Error":           err,
			})
	}
}

func addPeerGroups(ctx context.Context, bgpServer *server.BgpServer, addedPg []oc.PeerGroup) {
	for _, pg := range addedPg {
		bgpServer.Log().Info("Add PeerGroup",
			log.Fields{
				"Topic": "config",
				"Key":   pg.Config.PeerGroupName,
			})

		if err := bgpServer.AddPeerGroup(ctx, &api.AddPeerGroupRequest{
			PeerGroup: oc.NewPeerGroupFromConfigStruct(&pg),
		}); err != nil {
			bgpServer.Log().Fatal("Failed to add PeerGroup",
				log.Fields{
					log.FieldFacility: log.FacilityConfig,

					"Topic": "config",
					"Key":   pg.Config.PeerGroupName,
					"Error": err,
				})
		}
	}
}

func deletePeerGroups(ctx context.Context, bgpServer *server.BgpServer, deletedPg []oc.PeerGroup) {
	for _, pg := range deletedPg {
		bgpServer.Log().Info("delete PeerGroup",
			log.Fields{
				"Topic": "config",
				"Key":   pg.Config.PeerGroupName,
			})
		if err := bgpServer.DeletePeerGroup(ctx, &api.DeletePeerGroupRequest{
			Name: pg.Config.PeerGroupName,
		}); err != nil {
			bgpServer.Log().Fatal("Failed to delete PeerGroup",
				log.Fields{
					log.FieldFacility: log.FacilityConfig,

					"Topic": "config",
					"Key":   pg.Config.PeerGroupName,
					"Error": err,
				})
		}
	}
}

func updatePeerGroups(ctx context.Context, bgpServer *server.BgpServer, updatedPg []oc.PeerGroup) bool {
	for _, pg := range updatedPg {
		bgpServer.Log().Info("update PeerGroup",
			log.Fields{
				"Topic": "config",
				"Key":   pg.Config.PeerGroupName,
			})
		if u, err := bgpServer.UpdatePeerGroup(ctx, &api.UpdatePeerGroupRequest{
			PeerGroup: oc.NewPeerGroupFromConfigStruct(&pg),
		}); err != nil {
			bgpServer.Log().Fatal("Failed to update PeerGroup",
				log.Fields{
					log.FieldFacility: log.FacilityConfig,

					"Topic": "config",
					"Key":   pg.Config.PeerGroupName,
					"Error": err,
				})
		} else {
			return u.NeedsSoftResetIn
		}
	}
	return false
}

func addDynamicNeighbors(ctx context.Context, bgpServer *server.BgpServer, dynamicNeighbors []oc.DynamicNeighbor) {
	for _, dn := range dynamicNeighbors {
		bgpServer.Log().Info("Add Dynamic Neighbor to PeerGroup",
			log.Fields{
				"Topic":  "config",
				"Key":    dn.Config.PeerGroup,
				"Prefix": dn.Config.Prefix,
			})
		if err := bgpServer.AddDynamicNeighbor(ctx, &api.AddDynamicNeighborRequest{
			DynamicNeighbor: &api.DynamicNeighbor{
				Prefix:    dn.Config.Prefix,
				PeerGroup: dn.Config.PeerGroup,
			},
		}); err != nil {
			bgpServer.Log().Fatal("Failed to add Dynamic Neighbor to PeerGroup",
				log.Fields{
					log.FieldFacility: log.FacilityConfig,

					"Topic":  "config",
					"Key":    dn.Config.PeerGroup,
					"Prefix": dn.Config.Prefix,
					"Error":  err,
				})
		}
	}
}

func addNeighbors(ctx context.Context, bgpServer *server.BgpServer, added []oc.Neighbor) {
	for _, p := range added {
		bgpServer.Log().Info("Add Peer",
			log.Fields{
				"Topic": "config",
				"Key":   p.State.NeighborAddress,
			})
		if err := bgpServer.AddPeer(ctx, &api.AddPeerRequest{
			Peer: oc.NewPeerFromConfigStruct(&p),
		}); err != nil {
			bgpServer.Log().Fatal("Failed to add Peer",
				log.Fields{
					log.FieldFacility: log.FacilityConfig,

					"Topic": "config",
					"Key":   p.State.NeighborAddress,
					"Error": err,
				})
		}
	}
}

func deleteNeighbors(ctx context.Context, bgpServer *server.BgpServer, deleted []oc.Neighbor) {
	for _, p := range deleted {
		bgpServer.Log().Info("Delete Peer",
			log.Fields{
				"Topic": "config",
				"Key":   p.State.NeighborAddress,
			})
		if err := bgpServer.DeletePeer(ctx, &api.DeletePeerRequest{
			Address: p.State.NeighborAddress,
		}); err != nil {
			bgpServer.Log().Fatal("Failed to delete Peer",
				log.Fields{
					log.FieldFacility: log.FacilityConfig,

					"Topic": "config",
					"Key":   p.State.NeighborAddress,
					"Error": err,
				})
		}
	}
}

func updateNeighbors(ctx context.Context, bgpServer *server.BgpServer, updated []oc.Neighbor) bool {
	for _, p := range updated {
		bgpServer.Log().Info("Update Peer",
			log.Fields{
				"Topic": "config",
				"Key":   p.State.NeighborAddress,
			})
		if u, err := bgpServer.UpdatePeer(ctx, &api.UpdatePeerRequest{
			Peer: oc.NewPeerFromConfigStruct(&p),
		}); err != nil {
			bgpServer.Log().Fatal("Failed to update Peer",
				log.Fields{
					log.FieldFacility: log.FacilityConfig,

					"Topic": "config",
					"Key":   p.State.NeighborAddress,
					"Error": err,
				})
		} else {
			return u.NeedsSoftResetIn
		}
	}
	return false
}

// InitialConfig applies initial configuration to a pristine gobgp instance. It
// can only be called once for an instance. Subsequent changes to the
// configuration can be applied using UpdateConfig. The BgpConfigSet can be
// obtained by calling ReadConfigFile. If graceful restart behavior is desired,
// pass true for isGracefulRestart. Otherwise, pass false.
func InitialConfig(ctx context.Context, bgpServer *server.BgpServer, newConfig *oc.BgpConfigSet, isGracefulRestart bool) (*oc.BgpConfigSet, error) {
	if err := bgpServer.StartBgp(ctx, &api.StartBgpRequest{
		Global: oc.NewGlobalFromConfigStruct(&newConfig.Global),
	}); err != nil {
		bgpServer.Log().Fatal("failed to set global config",
			log.Fields{"Topic": "config", "Error": err})
	}

	if newConfig.Zebra.Config.Enabled {
		tps := newConfig.Zebra.Config.RedistributeRouteTypeList
		l := make([]string, 0, len(tps))
		l = append(l, tps...)
		if err := bgpServer.EnableZebra(ctx, &api.EnableZebraRequest{
			Url:                  newConfig.Zebra.Config.Url,
			RouteTypes:           l,
			Version:              uint32(newConfig.Zebra.Config.Version),
			NexthopTriggerEnable: newConfig.Zebra.Config.NexthopTriggerEnable,
			NexthopTriggerDelay:  uint32(newConfig.Zebra.Config.NexthopTriggerDelay),
			MplsLabelRangeSize:   newConfig.Zebra.Config.MplsLabelRangeSize,
			SoftwareName:         newConfig.Zebra.Config.SoftwareName,
		}); err != nil {
			bgpServer.Log().Fatal("failed to set zebra config",
				log.Fields{"Topic": "config", "Error": err})
		}
	}

	if len(newConfig.Collector.Config.Url) > 0 {
		bgpServer.Log().Fatal("collector feature is not supported",
			log.Fields{"Topic": "config"})
	}

	for _, c := range newConfig.RpkiServers {
		if err := bgpServer.AddRpki(ctx, &api.AddRpkiRequest{
			Address:  c.Config.Address,
			Port:     c.Config.Port,
			Lifetime: c.Config.RecordLifetime,
		}); err != nil {
			bgpServer.Log().Fatal("failed to set rpki config",
				log.Fields{"Topic": "config", "Error": err})
		}
	}
	f := func(t oc.BmpRouteMonitoringPolicyType) api.AddBmpRequest_MonitoringPolicy {
		switch t {
		case oc.BMP_ROUTE_MONITORING_POLICY_TYPE_PRE_POLICY:
			return api.AddBmpRequest_MONITORING_POLICY_PRE
		case oc.BMP_ROUTE_MONITORING_POLICY_TYPE_POST_POLICY:
			return api.AddBmpRequest_MONITORING_POLICY_POST
		case oc.BMP_ROUTE_MONITORING_POLICY_TYPE_BOTH:
			return api.AddBmpRequest_MONITORING_POLICY_BOTH
		case oc.BMP_ROUTE_MONITORING_POLICY_TYPE_LOCAL_RIB:
			return api.AddBmpRequest_MONITORING_POLICY_LOCAL
		case oc.BMP_ROUTE_MONITORING_POLICY_TYPE_ALL:
			return api.AddBmpRequest_MONITORING_POLICY_ALL
		}
		return api.AddBmpRequest_MONITORING_POLICY_UNSPECIFIED
	}

	for _, c := range newConfig.BmpServers {
		if err := bgpServer.AddBmp(ctx, &api.AddBmpRequest{
			Address:           c.Config.Address,
			Port:              c.Config.Port,
			SysName:           c.Config.SysName,
			SysDescr:          c.Config.SysDescr,
			Policy:            f(c.Config.RouteMonitoringPolicy),
			StatisticsTimeout: int32(c.Config.StatisticsTimeout),
		}); err != nil {
			bgpServer.Log().Fatal("failed to set bmp config",
				log.Fields{"Topic": "config", "Error": err})
		}
	}
	for _, vrf := range newConfig.Vrfs {
		rd, err := bgp.ParseRouteDistinguisher(vrf.Config.Rd)
		if err != nil {
			bgpServer.Log().Fatal("failed to load vrf rd config",
				log.Fields{"Topic": "config", "Error": err})
		}

		importRtList, err := marshalRouteTargets(vrf.Config.ImportRtList)
		if err != nil {
			bgpServer.Log().Fatal("failed to load vrf import rt config",
				log.Fields{"Topic": "config", "Error": err})
		}
		exportRtList, err := marshalRouteTargets(vrf.Config.ExportRtList)
		if err != nil {
			bgpServer.Log().Fatal("failed to load vrf export rt config",
				log.Fields{"Topic": "config", "Error": err})
		}

		a, err := apiutil.MarshalRD(rd)
		if err != nil {
			bgpServer.Log().Fatal("failed to set vrf config",
				log.Fields{"Topic": "config", "Error": err})
		}
		if err := bgpServer.AddVrf(ctx, &api.AddVrfRequest{
			Vrf: &api.Vrf{
				Name:     vrf.Config.Name,
				Rd:       a,
				Id:       vrf.Config.Id,
				ImportRt: importRtList,
				ExportRt: exportRtList,
			},
		}); err != nil {
			bgpServer.Log().Fatal("failed to set vrf config",
				log.Fields{"Topic": "config", "Error": err})
		}
	}
	for _, c := range newConfig.MrtDump {
		if len(c.Config.FileName) == 0 {
			continue
		}

		dump_type := api.EnableMrtRequest_DUMP_TYPE_UNSPECIFIED
		switch c.Config.DumpType {
		case oc.MRT_TYPE_UPDATES:
			dump_type = api.EnableMrtRequest_DUMP_TYPE_UPDATES
		case oc.MRT_TYPE_TABLE:
			dump_type = api.EnableMrtRequest_DUMP_TYPE_TABLE
		}

		if err := bgpServer.EnableMrt(ctx, &api.EnableMrtRequest{
			DumpType:         dump_type,
			Filename:         c.Config.FileName,
			DumpInterval:     c.Config.DumpInterval,
			RotationInterval: c.Config.RotationInterval,
		}); err != nil {
			bgpServer.Log().Fatal("failed to set mrt config",
				log.Fields{"Topic": "config", "Error": err})
		}
	}
	p := oc.ConfigSetToRoutingPolicy(newConfig)
	rp, err := table.NewAPIRoutingPolicyFromConfigStruct(p)
	if err != nil {
		bgpServer.Log().Fatal("failed to update policy config",
			log.Fields{"Topic": "config", "Error": err})
	} else if err := bgpServer.SetPolicies(ctx, &api.SetPoliciesRequest{
		DefinedSets: rp.DefinedSets,
		Policies:    rp.Policies,
	}); err != nil {
		bgpServer.Log().Fatal("failed to set policies",
			log.Fields{
				log.FieldFacility: log.FacilityConfig,
				"Topic":           "config",
				"Error":           err,
			})
	}

	assignGlobalpolicy(ctx, bgpServer, &newConfig.Global.ApplyPolicy.Config)

	added := newConfig.Neighbors
	addedPg := newConfig.PeerGroups
	if isGracefulRestart {
		for i, n := range added {
			if n.GracefulRestart.Config.Enabled {
				added[i].GracefulRestart.State.LocalRestarting = true
			}
		}
	}

	addPeerGroups(ctx, bgpServer, addedPg)
	addDynamicNeighbors(ctx, bgpServer, newConfig.DynamicNeighbors)
	addNeighbors(ctx, bgpServer, added)
	return newConfig, nil
}

// UpdateConfig updates the configuration of a running gobgp instance.
// InitialConfig must have been called once before this can be called for
// subsequent changes to config. The differences are that this call 1) does not
// hangle graceful restart and 2) requires a BgpConfigSet for the previous
// configuration so that it can compute the delta between it and the new
// config. The new BgpConfigSet can be obtained using ReadConfigFile.
func UpdateConfig(ctx context.Context, bgpServer *server.BgpServer, c, newConfig *oc.BgpConfigSet) (*oc.BgpConfigSet, error) {
	addedPg, deletedPg, updatedPg := oc.UpdatePeerGroupConfig(bgpServer.Log(), c, newConfig)
	added, deleted, updated := oc.UpdateNeighborConfig(bgpServer.Log(), c, newConfig)
	updatePolicy := oc.CheckPolicyDifference(bgpServer.Log(), oc.ConfigSetToRoutingPolicy(c), oc.ConfigSetToRoutingPolicy(newConfig))

	if updatePolicy {
		bgpServer.Log().Info("policy config is update", log.Fields{"Topic": "config"})
		p := oc.ConfigSetToRoutingPolicy(newConfig)
		rp, err := table.NewAPIRoutingPolicyFromConfigStruct(p)
		if err != nil {
			bgpServer.Log().Fatal("failed to update policy config",
				log.Fields{
					log.FieldFacility: log.FacilityConfig,
					"Topic":           "config",
					"Error":           err,
				})
		} else if err := bgpServer.SetPolicies(ctx, &api.SetPoliciesRequest{
			DefinedSets: rp.DefinedSets,
			Policies:    rp.Policies,
		}); err != nil {
			bgpServer.Log().Fatal("failed to set policies",
				log.Fields{
					log.FieldFacility: log.FacilityConfig,
					"Topic":           "config",
					"Error":           err,
				})
		}
	}
	// global policy update
	if !newConfig.Global.ApplyPolicy.Config.Equal(&c.Global.ApplyPolicy.Config) {
		assignGlobalpolicy(ctx, bgpServer, &newConfig.Global.ApplyPolicy.Config)
		updatePolicy = true
	}

	addPeerGroups(ctx, bgpServer, addedPg)
	deletePeerGroups(ctx, bgpServer, deletedPg)
	needsSoftResetIn := updatePeerGroups(ctx, bgpServer, updatedPg)
	updatePolicy = updatePolicy || needsSoftResetIn
	addDynamicNeighbors(ctx, bgpServer, newConfig.DynamicNeighbors)
	addNeighbors(ctx, bgpServer, added)
	deleteNeighbors(ctx, bgpServer, deleted)
	needsSoftResetIn = updateNeighbors(ctx, bgpServer, updated)
	updatePolicy = updatePolicy || needsSoftResetIn

	if updatePolicy {
		if err := bgpServer.ResetPeer(ctx, &api.ResetPeerRequest{
			Address:   "",
			Direction: api.ResetPeerRequest_DIRECTION_IN,
			Soft:      true,
		}); err != nil {
			bgpServer.Log().Fatal("failed to update policy config",
				log.Fields{"Topic": "config", "Error": err})
		}
	}
	return newConfig, nil
}
