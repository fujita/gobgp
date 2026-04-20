# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import time
import unittest

import collections
collections.Callable = collections.abc.Callable

import nose

from lib.noseplugin import OptionParser, parser_option

from lib import base
from lib.base import (
    assert_several_times,
    Bridge,
    BGP_FSM_ESTABLISHED,
    local,
)
from lib.gobgp import GoBGPContainer


class ZebraNHTTest(unittest.TestCase):
    """
    Test case for Next-Hop Tracking (NHT) with Zebra integration.

    Verifies that GoBGP correctly reacts to NEXTHOP_UPDATE messages from
    zebra by updating path MED and reachability, then propagating the
    changes to BGP peers.

    OSPF is intentionally not used: the required nexthop state changes are
    driven by static routes inside r2's zebra, which is deterministic and
    keeps the test free of IGP convergence timing.
    """

    # R1: GoBGP
    # R2: GoBGP + Zebra (static routes)
    #
    # +----+      +----+
    # | R1 |------| R2 |
    # +----+      +----+
    #
    # The nexthop 10.3.1.1 is created as a static route in r2's zebra.
    # Metric changes and reachability transitions are simulated by
    # re-adding or removing that static route with different distances.

    NEXTHOP = '10.3.1.1'
    PREFIX = '10.3.1.0/24'

    def _assert_med_equal(self, rt, prefix, med):
        rib = rt.get_global_rib(prefix=prefix)
        self.assertEqual(len(rib), 1)
        self.assertEqual(len(rib[0]['paths']), 1)
        self.assertEqual(rib[0]['paths'][0]['med'], med)

    def _set_static_nexthop(self, metric):
        # Point the static route at the r1-r2 bridge subnet gateway so
        # zebra treats it as reachable and reports the metric.
        # We use the default distance mechanism for metric: zebra passes
        # the configured metric to NEXTHOP_UPDATE.
        self.r2.local(
            "vtysh -c 'configure terminal'"
            " -c 'ip route %s/32 192.168.12.1 %d'"
            % (self.NEXTHOP, metric))

    def _remove_static_nexthop(self, metric):
        self.r2.local(
            "vtysh -c 'configure terminal'"
            " -c 'no ip route %s/32 192.168.12.1 %d'"
            % (self.NEXTHOP, metric))

    @classmethod
    def setUpClass(cls):
        gobgp_ctn_image_name = parser_option.gobgp_image
        base.TEST_PREFIX = parser_option.test_prefix
        cls.r1 = GoBGPContainer(
            name='r1', asn=65000, router_id='192.168.0.1',
            ctn_image_name=gobgp_ctn_image_name,
            log_level=parser_option.gobgp_log_level,
            zebra=False)

        cls.r2 = GoBGPContainer(
            name='r2', asn=65000, router_id='192.168.0.2',
            ctn_image_name=gobgp_ctn_image_name,
            log_level=parser_option.gobgp_log_level,
            zebra=True,
            zapi_version=3)

        wait_time = max(ctn.run() for ctn in [cls.r1, cls.r2])
        time.sleep(wait_time)

        cls.br_r1_r2 = Bridge(name='br_r1_r2', subnet='192.168.12.0/24')
        for ctn in (cls.r1, cls.r2):
            cls.br_r1_r2.addif(ctn)

    def test_01_BGP_neighbor_established(self):
        # Test to start BGP connection up between r1-r2.

        self.r1.add_peer(self.r2, bridge=self.br_r1_r2.name)
        self.r2.add_peer(self.r1, bridge=self.br_r1_r2.name)

        self.r1.wait_for(expected_state=BGP_FSM_ESTABLISHED, peer=self.r2)

    def test_02_reachable_nexthop(self):
        # Add a static route for the nexthop with metric 20. Adding a BGP
        # route whose nexthop is this prefix should result in MED=20 both
        # on r2 (originator) and r1 (receiver).
        self._set_static_nexthop(20)

        self.r2.local(
            'gobgp global rib add -a ipv4 %s nexthop %s'
            % (self.PREFIX, self.NEXTHOP))

        assert_several_times(
            f=lambda: self._assert_med_equal(self.r2, self.PREFIX, 20),
            t=60)
        assert_several_times(
            f=lambda: self._assert_med_equal(self.r1, self.PREFIX, 20),
            t=60)

    def test_03_metric_change(self):
        # Replace the static route with one of a different metric in a
        # single vtysh transaction so zebra never sees the nexthop as
        # unreachable. The path must transition directly from MED=20 to
        # MED=30 without any intermediate withdrawal to r1.
        self.r2.local(
            "vtysh -c 'configure terminal'"
            " -c 'ip route %s/32 192.168.12.1 30'"
            " -c 'no ip route %s/32 192.168.12.1 20'"
            % (self.NEXTHOP, self.NEXTHOP))

        assert_several_times(
            f=lambda: self._assert_med_equal(self.r2, self.PREFIX, 30),
            t=60)
        assert_several_times(
            f=lambda: self._assert_med_equal(self.r1, self.PREFIX, 30),
            t=60)

    def test_04_nexthop_unreachable(self):
        # Remove the static route entirely: nexthop becomes unreachable.
        # r2 must mark the path as not-best ('* '), and r1 must not have
        # the prefix in its table at all.
        self._remove_static_nexthop(30)

        def _r2_not_best():
            self.assertEqual(self.r2.local(
                "gobgp global rib -a ipv4 %s"
                " | grep '^* ' > /dev/null"  # not best "*>"
                " && echo OK || echo NG" % self.PREFIX,
                capture=True), 'OK')

        def _r1_no_prefix():
            self.assertEqual(self.r1.local(
                "gobgp global rib -a ipv4 %s"
                " | grep 'Network not in table' > /dev/null"
                " && echo OK || echo NG" % self.PREFIX,
                capture=True), 'OK')

        assert_several_times(f=_r2_not_best, t=60)
        assert_several_times(f=_r1_no_prefix, t=60)

    def test_05_add_path_while_unreachable(self):
        # Add a new path while the nexthop is unreachable. It must be
        # tracked as not-best on r2 and never advertised to r1.
        prefix = '10.3.2.0/24'
        self.r2.local(
            'gobgp global rib add -a ipv4 %s nexthop %s'
            % (prefix, self.NEXTHOP))

        def _r2_not_best():
            self.assertEqual(self.r2.local(
                "gobgp global rib -a ipv4 %s"
                " | grep '^* ' > /dev/null"
                " && echo OK || echo NG" % prefix,
                capture=True), 'OK')

        def _r1_no_prefix():
            self.assertEqual(self.r1.local(
                "gobgp global rib -a ipv4 %s"
                " | grep 'Network not in table' > /dev/null"
                " && echo OK || echo NG" % prefix,
                capture=True), 'OK')

        assert_several_times(f=_r2_not_best, t=60)
        assert_several_times(f=_r1_no_prefix, t=60)

    def test_06_nexthop_restore(self):
        # Re-add the static route with metric 20. Both paths (10.3.1.0/24
        # and 10.3.2.0/24) should become best on r2 and reach r1 with
        # MED=20.
        self._set_static_nexthop(20)

        assert_several_times(
            f=lambda: self._assert_med_equal(self.r2, self.PREFIX, 20),
            t=60)
        assert_several_times(
            f=lambda: self._assert_med_equal(self.r1, self.PREFIX, 20),
            t=60)
        assert_several_times(
            f=lambda: self._assert_med_equal(self.r2, '10.3.2.0/24', 20),
            t=60)
        assert_several_times(
            f=lambda: self._assert_med_equal(self.r1, '10.3.2.0/24', 20),
            t=60)


if __name__ == '__main__':
    output = local("which docker 2>&1 > /dev/null ; echo $?", capture=True)
    if int(output) != 0:
        print("docker not found")
        sys.exit(1)

    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
