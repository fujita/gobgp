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

package mrt

import (
	"bufio"
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

func TestMrtHdr(t *testing.T) {
	h1, err := NewMRTHeader(time.Unix(10, 0), TABLE_DUMPv2, RIB_IPV4_MULTICAST, 20)
	if err != nil {
		t.Fatal(err)
	}
	b1, err := h1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	h2 := &MRTHeader{}
	err = h2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, reflect.DeepEqual(h1, h2), true)
}

func TestMrtHdrTime(t *testing.T) {
	ttime1 := time.Unix(10, 0)
	h1, err := NewMRTHeader(ttime1, TABLE_DUMPv2, RIB_IPV4_MULTICAST, 20)
	if err != nil {
		t.Fatal(err)
	}
	h1time := h1.GetTime()
	t.Logf("this timestamp should be 10s after epoch:%v", h1time)
	assert.Equal(t, h1time, ttime1)

	ttime2 := time.Unix(20, 123000)
	h2, err := NewMRTHeader(ttime2, BGP4MP_ET, STATE_CHANGE, 20)
	if err != nil {
		t.Fatal(err)
	}
	h2time := h2.GetTime()
	t.Logf("this timestamp should be 20s and 123ms after epoch:%v", h2time)
	assert.Equal(t, h2time, ttime2)
}

func testPeer(t *testing.T, p1 *Peer) {
	b1, err := p1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	p2 := &Peer{}
	rest, err := p2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(rest), 0)
	assert.Equal(t, reflect.DeepEqual(p1, p2), true)
}

func TestMrtPeer(t *testing.T) {
	p := NewPeer("192.168.0.1", "10.0.0.1", 65000, false)
	testPeer(t, p)
}

func TestMrtPeerv6(t *testing.T) {
	p := NewPeer("192.168.0.1", "2001::1", 65000, false)
	testPeer(t, p)
}

func TestMrtPeerAS4(t *testing.T) {
	p := NewPeer("192.168.0.1", "2001::1", 135500, true)
	testPeer(t, p)
}

func TestMrtPeerIndexTable(t *testing.T) {
	p1 := NewPeer("192.168.0.1", "10.0.0.1", 65000, false)
	p2 := NewPeer("192.168.0.1", "2001::1", 65000, false)
	p3 := NewPeer("192.168.0.1", "2001::1", 135500, true)
	pt1 := NewPeerIndexTable("192.168.0.1", "test", []*Peer{p1, p2, p3})
	b1, err := pt1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	pt2 := &PeerIndexTable{}
	err = pt2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, reflect.DeepEqual(pt1, pt2), true)
}

func TestMrtRibEntry(t *testing.T) {
	aspath1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{1000}),
		bgp.NewAsPathParam(1, []uint16{1001, 1002}),
		bgp.NewAsPathParam(2, []uint16{1003, 1004}),
	}

	p := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(3),
		bgp.NewPathAttributeAsPath(aspath1),
		bgp.NewPathAttributeNextHop("129.1.1.2"),
		bgp.NewPathAttributeMultiExitDisc(1 << 20),
		bgp.NewPathAttributeLocalPref(1 << 22),
	}

	e1 := NewRibEntry(1, uint32(time.Now().Unix()), 0, p, false)
	b1, err := e1.Serialize(bgp.RF_IPv4_UC)
	if err != nil {
		t.Fatal(err)
	}

	e2 := &RibEntry{}
	rest, err := e2.DecodeFromBytes(b1, bgp.RF_IPv4_UC)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(rest), 0)
	assert.Equal(t, reflect.DeepEqual(e1, e2), true)
}

func TestMrtRibEntryWithAddPath(t *testing.T) {
	aspath1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{1000}),
		bgp.NewAsPathParam(1, []uint16{1001, 1002}),
		bgp.NewAsPathParam(2, []uint16{1003, 1004}),
	}

	p := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(3),
		bgp.NewPathAttributeAsPath(aspath1),
		bgp.NewPathAttributeNextHop("129.1.1.2"),
		bgp.NewPathAttributeMultiExitDisc(1 << 20),
		bgp.NewPathAttributeLocalPref(1 << 22),
	}
	e1 := NewRibEntry(1, uint32(time.Now().Unix()), 200, p, true)
	b1, err := e1.Serialize(bgp.RF_IPv4_UC)
	if err != nil {
		t.Fatal(err)
	}

	e2 := &RibEntry{isAddPath: true}
	rest, err := e2.DecodeFromBytes(b1, bgp.RF_IPv4_UC)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(rest), 0)
	assert.Equal(t, reflect.DeepEqual(e1, e2), true)
}

func TestMrtRib(t *testing.T) {
	aspath1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{1000}),
		bgp.NewAsPathParam(1, []uint16{1001, 1002}),
		bgp.NewAsPathParam(2, []uint16{1003, 1004}),
	}

	p := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(3),
		bgp.NewPathAttributeAsPath(aspath1),
		bgp.NewPathAttributeNextHop("129.1.1.2"),
		bgp.NewPathAttributeMultiExitDisc(1 << 20),
		bgp.NewPathAttributeLocalPref(1 << 22),
	}

	e1 := NewRibEntry(1, uint32(time.Now().Unix()), 0, p, false)
	e2 := NewRibEntry(2, uint32(time.Now().Unix()), 0, p, false)
	e3 := NewRibEntry(3, uint32(time.Now().Unix()), 0, p, false)

	r1 := NewRib(1, bgp.NewIPAddrPrefix(24, "192.168.0.0"), []*RibEntry{e1, e2, e3})
	b1, err := r1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	r2 := &Rib{
		Family: bgp.RF_IPv4_UC,
	}
	err = r2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, reflect.DeepEqual(r1, r2), true)
}

func TestMrtRibWithAddPath(t *testing.T) {
	aspath1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{1000}),
		bgp.NewAsPathParam(1, []uint16{1001, 1002}),
		bgp.NewAsPathParam(2, []uint16{1003, 1004}),
	}

	p := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(3),
		bgp.NewPathAttributeAsPath(aspath1),
		bgp.NewPathAttributeNextHop("129.1.1.2"),
		bgp.NewPathAttributeMultiExitDisc(1 << 20),
		bgp.NewPathAttributeLocalPref(1 << 22),
	}

	e1 := NewRibEntry(1, uint32(time.Now().Unix()), 100, p, true)
	e2 := NewRibEntry(2, uint32(time.Now().Unix()), 200, p, true)
	e3 := NewRibEntry(3, uint32(time.Now().Unix()), 300, p, true)

	r1 := NewRib(1, bgp.NewIPAddrPrefix(24, "192.168.0.0"), []*RibEntry{e1, e2, e3})
	b1, err := r1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	r2 := &Rib{
		Family:    bgp.RF_IPv4_UC,
		isAddPath: true,
	}
	err = r2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, reflect.DeepEqual(r1, r2), true)
}

func TestMrtGeoPeerTable(t *testing.T) {
	p1 := NewGeoPeer("192.168.0.1", 28.031157, 86.899684)
	p2 := NewGeoPeer("192.168.0.1", 35.360556, 138.727778)
	pt1 := NewGeoPeerTable("192.168.0.1", 12.345678, 98.765432, []*GeoPeer{p1, p2})
	b1, err := pt1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	pt2 := &GeoPeerTable{}
	err = pt2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, reflect.DeepEqual(pt1, pt2), true)
}

func TestMrtBgp4mpStateChange(t *testing.T) {
	c1 := NewBGP4MPStateChange(65000, 65001, 1, "192.168.0.1", "192.168.0.2", false, ACTIVE, ESTABLISHED)
	b1, err := c1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	c2 := &BGP4MPStateChange{BGP4MPHeader: &BGP4MPHeader{}}
	err = c2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, reflect.DeepEqual(c1, c2), true)
}

func TestMrtBgp4mpMessage(t *testing.T) {
	msg := bgp.NewBGPKeepAliveMessage()
	m1 := NewBGP4MPMessage(65000, 65001, 1, "192.168.0.1", "192.168.0.2", false, msg)
	b1, err := m1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	m2 := &BGP4MPMessage{BGP4MPHeader: &BGP4MPHeader{}}
	err = m2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, reflect.DeepEqual(m1, m2), true)
}

func TestMrtSplit(t *testing.T) {
	var b bytes.Buffer
	numwrite, numread := 10, 0
	for range numwrite {
		msg := bgp.NewBGPKeepAliveMessage()
		m1 := NewBGP4MPMessage(65000, 65001, 1, "192.168.0.1", "192.168.0.2", false, msg)
		mm, _ := NewMRTMessage(time.Unix(1234, 0), BGP4MP, MESSAGE, m1)
		b1, err := mm.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		b.Write(b1)
	}
	t.Logf("wrote %d serialized MRT keepalives in the buffer", numwrite)
	r := bytes.NewReader(b.Bytes())
	scanner := bufio.NewScanner(r)
	scanner.Split(SplitMrt)
	for scanner.Scan() {
		numread += 1
	}
	t.Logf("scanner scanned %d serialized keepalives from the buffer", numread)
	assert.Equal(t, numwrite, numread)
}

//nolint:errcheck
func FuzzMRT(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < MRT_COMMON_HEADER_LEN {
			return
		}

		hdr := &MRTHeader{}
		err := hdr.DecodeFromBytes(data[:MRT_COMMON_HEADER_LEN])
		if err != nil {
			return
		}

		ParseMRTBody(hdr, data[MRT_COMMON_HEADER_LEN:])
	})
}

// grep -r DecodeFromBytes pkg/packet/mrt/ | grep -e ":func " | perl -pe 's|func \(.* \*(.*?)\).*|(&\1\{\})\.DecodeFromBytes(data)|g' | awk -F ':' '{print $2}'
//
//nolint:errcheck
func FuzzDecodeFromBytes(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		(&MRTHeader{}).DecodeFromBytes(data)
		(&Peer{}).DecodeFromBytes(data)
		(&PeerIndexTable{}).DecodeFromBytes(data)
		(&RibEntry{}).DecodeFromBytes(data, bgp.RF_IPv4_UC)
		(&RibEntry{isAddPath: true}).DecodeFromBytes(data, bgp.RF_IPv4_UC)
		(&Rib{}).DecodeFromBytes(data)
		(&Rib{isAddPath: true}).DecodeFromBytes(data)
		(&GeoPeer{}).DecodeFromBytes(data)
		(&GeoPeerTable{}).DecodeFromBytes(data)
		if len(data) > 12 {
			h := &BGP4MPHeader{isAS4: true}
			_, err := h.decodeFromBytes(data[:12])
			if err != nil {
				return
			}
			(&BGP4MPStateChange{BGP4MPHeader: h}).DecodeFromBytes(data[12:])
			(&BGP4MPMessage{BGP4MPHeader: h}).DecodeFromBytes(data[12:])
		}
		if len(data) > 8 {
			h := &BGP4MPHeader{isAS4: false}
			_, err := h.decodeFromBytes(data[:8])
			if err != nil {
				return
			}
			(&BGP4MPStateChange{BGP4MPHeader: h}).DecodeFromBytes(data[8:])
			(&BGP4MPMessage{BGP4MPHeader: h}).DecodeFromBytes(data[8:])
		}
	})
}
