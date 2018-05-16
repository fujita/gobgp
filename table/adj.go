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

type AdjRib struct {
	tableManager *TableManager
	pInfo        *PeerInfo
	count        map[bgp.RouteFamily]int
	accepted     map[bgp.RouteFamily]int
}

func NewAdjRib(t *TableManager, pi *PeerInfo, rfList []bgp.RouteFamily) *AdjRib {
	for _, family := range rfList {
		if _, ok := t.Tables[family]; !ok {
			t.Tables[family] = NewTable(family)
		}
	}
	return &AdjRib{
		tableManager: t,
		pInfo:        pi,
		count:        make(map[bgp.RouteFamily]int),
		accepted:     make(map[bgp.RouteFamily]int),
	}
}

func (a *AdjRib) Update(newPath *Path) {
	t := a.tableManager.Tables[newPath.GetRouteFamily()]
	d := t.getOrCreateDest(newPath.GetNlri())
	old := d.updateAdjIn(newPath)
	family := newPath.GetRouteFamily()
	if newPath.IsWithdraw {
		if old != nil {
			a.dropPath(old)
		}
	} else {
		if old != nil {
			if old.IsAsLooped() && !newPath.IsLLGRStale() {
				a.accepted[family]++
			} else if !old.IsAsLooped() && newPath.IsLLGRStale() {
				a.accepted[family]--
			}
		} else {
			a.count[family]++
			if !newPath.IsAsLooped() {
				a.accepted[family]++
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
	for _, f := range rfList {
		count += a.count[f]
	}
	return count
}

func (a *AdjRib) Accepted(rfList []bgp.RouteFamily) int {
	accepted := 0
	for _, f := range rfList {
		accepted += a.accepted[f]
	}
	return accepted
}

func (a *AdjRib) dropPath(path *Path) {
	f := path.GetRouteFamily()
	a.count[f]--
	if !path.IsAsLooped() {
		a.accepted[f]--
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
	if _, ok := a.tableManager.Tables[family]; !ok {
		return nil, fmt.Errorf("%s unsupported", family)
	} else {
		return &TableInfo{
			NumDestination: a.count[family],
			NumPath:        a.count[family],
			NumAccepted:    a.accepted[family],
		}, nil
	}
}
