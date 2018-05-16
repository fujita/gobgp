// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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

	"github.com/osrg/gobgp/packet/bgp"
)

type ribState struct {
	accepted int
	count    int
}

type AdjRib struct {
	state        map[bgp.RouteFamily]ribState
	tableManager *TableManager
	pInfo        *PeerInfo
}

func NewAdjRib(t *TableManager, pi *PeerInfo, rfList []bgp.RouteFamily) *AdjRib {
	table := make(map[bgp.RouteFamily]map[string]*Path)
	for _, rf := range rfList {
		table[rf] = make(map[string]*Path)
	}
	return &AdjRib{
		pInfo:        pi,
		tableManager: t,
		state:        make(map[bgp.RouteFamily]ribState),
	}
}

func (a *AdjRib) Update(newPath *Path) {
	t := a.tableManager.Tables[newPath.GetRouteFamily()]
	d := t.getOrCreateDest(newPath.GetNlri())
	old := d.updateAdjIn(newPath)
	s := a.state[newPath.GetRouteFamily()]
	if newPath.IsWithdraw {
		if old != nil {
			a.dropPath(old)
		}
	} else {
		if old != nil {
			if old.IsAsLooped() && !newPath.IsLLGRStale() {
				s.accepted++
			} else if !old.IsAsLooped() && newPath.IsLLGRStale() {
				s.accepted--
			}
		} else {
			s.count++
			if !newPath.IsAsLooped() {
				s.accepted++
			}
		}
	}
}

func (a *AdjRib) pathList(rfList []bgp.RouteFamily, f func(*Destination)) {
	for _, t := range a.tableManager.tables(rfList...) {
		for _, d := range t.GetDestinations() {
			f(d)
		}
	}
}

func (a *AdjRib) PathList(rfList []bgp.RouteFamily, accepted bool) []*Path {
	pathList := make([]*Path, 0, a.Count(rfList))
	a.pathList(rfList, func(d *Destination) {
		for _, p := range d.adjInPathList {
			if p.GetSource() == a.pInfo {
				if accepted && p.IsAsLooped() {
					continue
				}
				pathList = append(pathList, p)
			}
		}
	})
	return pathList
}

func (a *AdjRib) Count(rfList []bgp.RouteFamily) int {
	count := 0
	for _, rf := range rfList {
		if _, ok := a.state[rf]; ok {
			count += a.state[rf].count
		}
	}
	return count
}

func (a *AdjRib) Accepted(rfList []bgp.RouteFamily) int {
	accepted := 0
	for _, rf := range rfList {
		if _, ok := a.state[rf]; ok {
			accepted += a.state[rf].accepted
		}
	}
	return accepted
}

func (a *AdjRib) dropPath(path *Path) {
	s := a.state[path.GetRouteFamily()]
	s.count--
	if !path.IsAsLooped() {
		s.accepted--
	}
}

func (a *AdjRib) Drop(rfList []bgp.RouteFamily) {
	a.pathList(rfList, func(d *Destination) {
		pathList := make([]*Path, 0, len(d.adjInPathList))
		for _, p := range d.adjInPathList {
			if p.GetSource() == a.pInfo {
				a.dropPath(p)
			} else {
				pathList = append(pathList, p)
			}
		}
		d.adjInPathList = pathList
	})
}

func (a *AdjRib) DropStale(rfList []bgp.RouteFamily) []*Path {
	dropped := make([]*Path, 0, a.Count(rfList))
	a.pathList(rfList, func(d *Destination) {
		pathList := make([]*Path, 0, len(d.adjInPathList))
		for _, p := range d.adjInPathList {
			if p.GetSource() == a.pInfo && p.IsStale() {
				dropped = append(dropped, p.Clone(true))
				a.dropPath(p)
			} else {
				pathList = append(pathList, p)
			}
		}
		d.adjInPathList = pathList
	})
	return dropped
}

func (a *AdjRib) StaleAll(rfList []bgp.RouteFamily) []*Path {
	pathList := make([]*Path, 0, a.Count(rfList))
	a.pathList(rfList, func(d *Destination) {
		for i, p := range d.adjInPathList {
			if p.GetSource() == a.pInfo {
				n := p.Clone(false)
				n.MarkStale(true)
				d.adjInPathList[i] = n
				pathList = append(pathList, n)
			}
		}
	})
	return pathList
}

func (a *AdjRib) Select(family bgp.RouteFamily, accepted bool, option ...TableSelectOption) (*Table, error) {
	option = append(option, TableSelectOption{adj: a.pInfo})
	if t, y := a.tableManager.Tables[family]; y {
		return t.Select(option...)
	}
	return NewTable(family), nil
}

func (a *AdjRib) TableInfo(family bgp.RouteFamily) (*TableInfo, error) {
	if s, ok := a.state[family]; !ok {
		return nil, fmt.Errorf("%s unsupported", family)
	} else {
		return &TableInfo{
			NumDestination: s.count,
			NumPath:        s.count,
			NumAccepted:    s.accepted,
		}, nil
	}
}
