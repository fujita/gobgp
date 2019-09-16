// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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

package table

import (
	"fmt"
	"math/bits"
	"net"
	"strings"

	"github.com/armon/go-radix"
	"github.com/osrg/critbitgo"
	"github.com/osrg/gobgp/pkg/packet/bgp"
	log "github.com/sirupsen/logrus"
)

type LookupOption uint8

const (
	LOOKUP_EXACT LookupOption = iota
	LOOKUP_LONGER
	LOOKUP_SHORTER
)

type LookupPrefix struct {
	Prefix string
	LookupOption
}

type TableSelectOption struct {
	ID             string
	AS             uint32
	LookupPrefixes []*LookupPrefix
	VRF            *Vrf
	adj            bool
	Best           bool
	MultiPath      bool
}

type entry interface {
	set(*Destination)
	get(bgp.AddrPrefixInterface) *Destination
	delete(bgp.AddrPrefixInterface)
	walk(func(*Destination) bool)
	count() int
}

type cri struct {
	n *critbitgo.Net
}

func (c *cri) key(nlri bgp.AddrPrefixInterface) *net.IPNet {
	switch T := nlri.(type) {
	case *bgp.IPAddrPrefix:
		return &net.IPNet{
			IP:   net.IP(T.Prefix.To4()),
			Mask: net.CIDRMask(int(T.Length), 32),
		}
	case *bgp.IPv6AddrPrefix:
		return &net.IPNet{
			IP:   net.IP(T.Prefix.To16()),
			Mask: net.CIDRMask(int(T.Length), 128),
		}
	}
	return nil
}

func (c *cri) set(d *Destination) {
	c.n.Add(c.key(d.nlri), d)
}

func (c *cri) get(nlri bgp.AddrPrefixInterface) *Destination {
	v, ok, _ := c.n.Get(c.key(nlri))
	if ok {
		return v.(*Destination)
	}
	return nil
}

func (c *cri) delete(nlri bgp.AddrPrefixInterface) {
	c.n.Delete(c.key(nlri))
}

func (c *cri) walk(fn func(*Destination) bool) {
	if c.n.Size() == 0 {
		return
	}
	c.n.Walk(func(_ *net.IPNet, value interface{}) bool {
		fn(value.(*Destination))
		return true
	})
}

func (c *cri) count() int {
	return c.n.Size()
}

type hashmap struct {
	destinations map[string]*Destination
}

func (m *hashmap) key(nlri bgp.AddrPrefixInterface) string {
	return nlri.String()
}

func (m *hashmap) set(d *Destination) {
	m.destinations[m.key(d.nlri)] = d
}

func (m *hashmap) get(nlri bgp.AddrPrefixInterface) *Destination {
	return m.destinations[m.key(nlri)]
}

func (m *hashmap) delete(nlri bgp.AddrPrefixInterface) {
	delete(m.destinations, m.key(nlri))
	if len(m.destinations) == 0 {
		m.destinations = make(map[string]*Destination)
	}
}

func (m *hashmap) walk(fn func(*Destination) bool) {
	for _, d := range m.destinations {
		if fn(d) {
			return
		}
	}
}

func (m *hashmap) count() int {
	return len(m.destinations)
}

type Table struct {
	routeFamily bgp.RouteFamily
	entry       entry
}

func NewTable(rf bgp.RouteFamily, dsts ...*Destination) *Table {
	var e entry
	switch rf {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		e = &cri{
			critbitgo.NewNet(),
		}
	default:
		e = &hashmap{
			destinations: make(map[string]*Destination),
		}
	}

	t := &Table{
		routeFamily: rf,
		entry:       e,
	}
	for _, dst := range dsts {
		t.entry.set(dst)
	}
	return t
}

func (t *Table) GetRoutefamily() bgp.RouteFamily {
	return t.routeFamily
}

func (t *Table) Get(nlri bgp.AddrPrefixInterface) *Destination {
	return t.entry.get(nlri)
}

func (t *Table) Walk(fn func(d *Destination) bool) {
	t.entry.walk(fn)
}

func (t *Table) Count() int {
	return t.entry.count()
}

func (t *Table) deletePathsByVrf(vrf *Vrf) []*Path {
	pathList := make([]*Path, 0)
	t.entry.walk(func(d *Destination) bool {
		for _, p := range d.knownPathList {
			var rd bgp.RouteDistinguisherInterface
			nlri := p.GetNlri()
			switch v := nlri.(type) {
			case *bgp.LabeledVPNIPAddrPrefix:
				rd = v.RD
			case *bgp.LabeledVPNIPv6AddrPrefix:
				rd = v.RD
			case *bgp.EVPNNLRI:
				rd = v.RD()
			default:
				continue
			}
			if p.IsLocal() && vrf.Rd.String() == rd.String() {
				pathList = append(pathList, p.Clone(true))
				break
			}
		}
		return false
	})

	return pathList
}

func (t *Table) deleteRTCPathsByVrf(vrf *Vrf, vrfs map[string]*Vrf) []*Path {
	pathList := make([]*Path, 0)
	if t.routeFamily != bgp.RF_RTC_UC {
		return pathList
	}
	for _, target := range vrf.ImportRt {
		lhs := target.String()
		t.entry.walk(func(d *Destination) bool {
			nlri := d.GetNlri().(*bgp.RouteTargetMembershipNLRI)
			rhs := nlri.RouteTarget.String()
			if lhs == rhs && isLastTargetUser(vrfs, target) {
				for _, p := range d.knownPathList {
					if p.IsLocal() {
						pathList = append(pathList, p.Clone(true))
						break
					}
				}
			}
			return false
		})
	}
	return pathList
}

func (t *Table) deleteDest(dest *Destination) {
	count := 0
	for _, v := range dest.localIdMap.bitmap {
		count += bits.OnesCount64(v)
	}
	if len(dest.localIdMap.bitmap) != 0 && count != 1 {
		return
	}
	t.entry.delete(dest.GetNlri())
}

func (t *Table) validatePath(path *Path) {
	if path == nil {
		log.WithFields(log.Fields{
			"Topic": "Table",
			"Key":   t.routeFamily,
		}).Error("path is nil")
	}
	if path.GetRouteFamily() != t.routeFamily {
		log.WithFields(log.Fields{
			"Topic":      "Table",
			"Key":        t.routeFamily,
			"Prefix":     path.GetNlri().String(),
			"ReceivedRf": path.GetRouteFamily().String(),
		}).Error("Invalid path. RouteFamily mismatch")
	}
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH); attr != nil {
		pathParam := attr.(*bgp.PathAttributeAsPath).Value
		for _, as := range pathParam {
			_, y := as.(*bgp.As4PathParam)
			if !y {
				log.WithFields(log.Fields{
					"Topic": "Table",
					"Key":   t.routeFamily,
					"As":    as,
				}).Fatal("AsPathParam must be converted to As4PathParam")
			}
		}
	}
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS4_PATH); attr != nil {
		log.WithFields(log.Fields{
			"Topic": "Table",
			"Key":   t.routeFamily,
		}).Fatal("AS4_PATH must be converted to AS_PATH")
	}
	if path.GetNlri() == nil {
		log.WithFields(log.Fields{
			"Topic": "Table",
			"Key":   t.routeFamily,
		}).Fatal("path's nlri is nil")
	}
}

func (t *Table) getOrCreateDest(nlri bgp.AddrPrefixInterface, size int) *Destination {
	dest := t.entry.get(nlri)
	// If destination for given prefix does not exist we create it.
	if dest == nil {
		log.WithFields(log.Fields{
			"Topic": "Table",
			"Nlri":  nlri,
		}).Debugf("create Destination")
		dest = NewDestination(nlri, size)
		t.entry.set(dest)
	}
	return dest
}

func (t *Table) GetLongerPrefixDestinations(key string) ([]*Destination, error) {
	results := make([]*Destination, 0, t.entry.count())
	switch t.routeFamily {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC, bgp.RF_IPv4_MPLS, bgp.RF_IPv6_MPLS:
		_, prefix, err := net.ParseCIDR(key)
		if err != nil {
			return nil, err
		}
		k := CidrToRadixkey(prefix.String())
		r := radix.New()
		t.entry.walk(func(d *Destination) bool {
			r.Insert(AddrToRadixkey(d.nlri), d)
			return false
		})
		r.WalkPrefix(k, func(s string, v interface{}) bool {
			results = append(results, v.(*Destination))
			return false
		})
	default:
		t.entry.walk(func(d *Destination) bool {
			results = append(results, d)
			return false
		})
	}
	return results, nil
}

func (t *Table) GetEvpnDestinationsWithRouteType(typ string) ([]*Destination, error) {
	var routeType uint8
	switch strings.ToLower(typ) {
	case "a-d":
		routeType = bgp.EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY
	case "macadv":
		routeType = bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT
	case "multicast":
		routeType = bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG
	case "esi":
		routeType = bgp.EVPN_ETHERNET_SEGMENT_ROUTE
	case "prefix":
		routeType = bgp.EVPN_IP_PREFIX
	default:
		return nil, fmt.Errorf("unsupported evpn route type: %s", typ)
	}
	results := make([]*Destination, 0, t.entry.count())
	var err error
	switch t.routeFamily {
	case bgp.RF_EVPN:
		t.entry.walk(func(d *Destination) bool {
			if nlri, ok := d.nlri.(*bgp.EVPNNLRI); !ok {
				err = fmt.Errorf("invalid evpn nlri type detected: %T", d.nlri)
				return true
			} else if nlri.RouteType == routeType {
				results = append(results, d)
			}
			return false
		})
	default:
		t.entry.walk(func(d *Destination) bool {
			results = append(results, d)
			return false
		})
	}
	return results, err
}

func (t *Table) Bests(id string, as uint32) []*Path {
	paths := make([]*Path, 0, t.entry.count())
	t.entry.walk(func(d *Destination) bool {
		path := d.GetBestPath(id, as)
		if path != nil {
			paths = append(paths, path)
		}
		return false
	})
	return paths
}

func (t *Table) MultiBests(id string) [][]*Path {
	paths := make([][]*Path, 0, t.entry.count())
	t.entry.walk(func(d *Destination) bool {
		path := d.GetMultiBestPath(id)
		if path != nil {
			paths = append(paths, path)
		}
		return false
	})
	return paths
}

func (t *Table) GetKnownPathList(id string, as uint32) []*Path {
	paths := make([]*Path, 0, t.entry.count())
	t.entry.walk(func(d *Destination) bool {
		paths = append(paths, d.GetKnownPathList(id, as)...)
		return false
	})
	return paths
}

func (t *Table) Select(option ...TableSelectOption) (*Table, error) {
	id := GLOBAL_RIB_NAME
	var vrf *Vrf
	adj := false
	prefixes := make([]*LookupPrefix, 0, len(option))
	best := false
	mp := false
	as := uint32(0)
	for _, o := range option {
		if o.ID != "" {
			id = o.ID
		}
		if o.VRF != nil {
			vrf = o.VRF
		}
		adj = o.adj
		prefixes = append(prefixes, o.LookupPrefixes...)
		best = o.Best
		mp = o.MultiPath
		as = o.AS
	}
	dOption := DestinationSelectOption{ID: id, AS: as, VRF: vrf, adj: adj, Best: best, MultiPath: mp}
	r := NewTable(t.routeFamily)

	if len(prefixes) != 0 {
		switch t.routeFamily {
		case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
			f := func(prefixStr string) bool {
				var nlri bgp.AddrPrefixInterface
				if t.routeFamily == bgp.RF_IPv4_UC {
					nlri, _ = bgp.NewPrefixFromRouteFamily(bgp.AFI_IP, bgp.SAFI_UNICAST, prefixStr)
				} else {
					nlri, _ = bgp.NewPrefixFromRouteFamily(bgp.AFI_IP6, bgp.SAFI_UNICAST, prefixStr)
				}
				if dst := t.entry.get(nlri); dst != nil {
					if d := dst.Select(dOption); d != nil {
						r.entry.set(d)
						return true
					}
				}
				return false
			}

			for _, p := range prefixes {
				key := p.Prefix
				switch p.LookupOption {
				case LOOKUP_LONGER:
					ds, err := t.GetLongerPrefixDestinations(key)
					if err != nil {
						return nil, err
					}
					for _, dst := range ds {
						if d := dst.Select(dOption); d != nil {
							r.entry.set(d)
						}
					}
				case LOOKUP_SHORTER:
					addr, prefix, err := net.ParseCIDR(key)
					if err != nil {
						return nil, err
					}
					ones, _ := prefix.Mask.Size()
					for i := ones; i >= 0; i-- {
						_, prefix, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", addr.String(), i))
						f(prefix.String())
					}
				default:
					if host := net.ParseIP(key); host != nil {
						masklen := 32
						if t.routeFamily == bgp.RF_IPv6_UC {
							masklen = 128
						}
						for i := masklen; i >= 0; i-- {
							_, prefix, err := net.ParseCIDR(fmt.Sprintf("%s/%d", key, i))
							if err != nil {
								return nil, err
							}
							if f(prefix.String()) {
								break
							}
						}
					} else {
						f(key)
					}
				}
			}
		case bgp.RF_EVPN:
			for _, p := range prefixes {
				// Uses LookupPrefix.Prefix as EVPN Route Type string
				ds, err := t.GetEvpnDestinationsWithRouteType(p.Prefix)
				if err != nil {
					return nil, err
				}
				for _, dst := range ds {
					if d := dst.Select(dOption); d != nil {
						r.entry.set(d)
					}
				}
			}
		default:
			return nil, fmt.Errorf("route filtering is not supported for this family")
		}
	} else {
		t.entry.walk(func(dst *Destination) bool {
			if d := dst.Select(dOption); d != nil {
				r.entry.set(d)
			}
			return false
		})
	}
	return r, nil
}

type TableInfo struct {
	NumDestination int
	NumPath        int
	NumAccepted    int
}

func (t *Table) Info(id string, as uint32) *TableInfo {
	var numD, numP int
	t.entry.walk(func(d *Destination) bool {
		n := 0
		if id == GLOBAL_RIB_NAME {
			n = len(d.knownPathList)
		} else {
			n = len(d.GetKnownPathList(id, as))
		}
		if n != 0 {
			numD++
			numP += n
		}
		return false
	})
	return &TableInfo{
		NumDestination: numD,
		NumPath:        numP,
	}
}
