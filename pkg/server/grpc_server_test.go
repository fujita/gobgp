package server

import (
	"fmt"
	"testing"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

func TestParseHost(t *testing.T) {
	tsts := []struct {
		name          string
		host          string
		expectNetwork string
		expectAddr    string
	}{
		{
			name:          "schemeless tcp host defaults to tcp",
			host:          "127.0.0.1:50051",
			expectNetwork: "tcp",
			expectAddr:    "127.0.0.1:50051",
		},
		{
			name:          "schemeless with only port defaults to tcp",
			host:          ":50051",
			expectNetwork: "tcp",
			expectAddr:    ":50051",
		},
		{
			name:          "unix socket",
			host:          "unix:///var/run/gobgp.socket",
			expectNetwork: "unix",
			expectAddr:    "/var/run/gobgp.socket",
		},
	}

	for _, tst := range tsts {
		t.Run(tst.name, func(t *testing.T) {
			gotNetwork, gotAddr := parseHost(tst.host)
			assert.Equal(t, tst.expectNetwork, gotNetwork)
			assert.Equal(t, tst.expectAddr, gotAddr)
		})
	}
}

func TestApi2PathWithBinaryNlri(t *testing.T) {
	var path = &api.Path{}

	path.Family = &api.Family{
		Afi:  api.Family_AFI_IP6,
		Safi: api.Family_SAFI_UNICAST,
	}
	nlri_string := "2a01:4b00:88b8:3a00:20c:29ff:fec8:20c5"
	nexthop_string := "2a01:4b00:88b8:3a00:20c:29ff:fec8:1"
	pr := bgp.NewIPv6AddrPrefix(128, nlri_string)
	bp, _ := pr.Serialize()
	path.NlriBinary = bp
	a := bgp.NewPathAttributeMpReachNLRI(nexthop_string, []bgp.AddrPrefixInterface{pr})
	b, _ := a.Serialize()
	path.PattrsBinary = append(path.PattrsBinary, b)
	p, err := api2Path(api.TableType_GLOBAL, path, false)
	assert.NoError(t, err)
	fmt.Println(p.GetNlri())
	assert.Equal(t, p.GetNlri(), pr)
}
