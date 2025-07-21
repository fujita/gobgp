// Copyright (C) 2014-2021 Nippon Telegraph and Telephone Corporation.
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
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/eapache/channels"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/internal/pkg/version"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
)

const (
	minConnectRetryInterval = 1
)

type fsmStateReasonType uint8

const (
	fsmDying fsmStateReasonType = iota
	fsmAdminDown
	fsmReadFailed
	fsmWriteFailed
	fsmNotificationSent
	fsmNotificationRecv
	fsmHoldTimerExpired
	fsmIdleTimerExpired
	fsmRestartTimerExpired
	fsmGracefulRestart
	fsmInvalidMsg
	fsmNewConnection
	fsmOpenMsgReceived
	fsmOpenMsgNegotiated
	fsmHardReset
	fsmDeConfigured
)

type fsmStateReason struct {
	Type            fsmStateReasonType
	BGPNotification *bgp.BGPMessage
	open            *bgp.BGPMessage
	Data            []byte
}

func newfsmStateReason(typ fsmStateReasonType, notif *bgp.BGPMessage, data []byte) *fsmStateReason {
	return &fsmStateReason{
		Type:            typ,
		BGPNotification: notif,
		Data:            data,
	}
}

func (r fsmStateReason) String() string {
	switch r.Type {
	case fsmDying:
		return "dying"
	case fsmAdminDown:
		return "admin-down"
	case fsmReadFailed:
		return "read-failed"
	case fsmWriteFailed:
		return "write-failed"
	case fsmNotificationSent:
		body := r.BGPNotification.Body.(*bgp.BGPNotification)
		return fmt.Sprintf("notification-sent %s", bgp.NewNotificationErrorCode(body.ErrorCode, body.ErrorSubcode).String())
	case fsmNotificationRecv:
		body := r.BGPNotification.Body.(*bgp.BGPNotification)
		return fmt.Sprintf("notification-received %s", bgp.NewNotificationErrorCode(body.ErrorCode, body.ErrorSubcode).String())
	case fsmHoldTimerExpired:
		return "hold-timer-expired"
	case fsmIdleTimerExpired:
		return "idle-hold-timer-expired"
	case fsmRestartTimerExpired:
		return "restart-timer-expired"
	case fsmGracefulRestart:
		return "graceful-restart"
	case fsmInvalidMsg:
		return "invalid-msg"
	case fsmNewConnection:
		return "new-connection"
	case fsmOpenMsgReceived:
		return "open-msg-received"
	case fsmOpenMsgNegotiated:
		return "open-msg-negotiated"
	case fsmHardReset:
		return "hard-reset"
	default:
		return "unknown"
	}
}

type fsmMsgType int

const (
	_ fsmMsgType = iota
	fsmMsgStateChange
	fsmMsgBGPMessage
	fsmMsgRouteRefresh
)

type fsmMsg struct {
	MsgType     fsmMsgType
	MsgSrc      string
	MsgData     any
	StateReason *fsmStateReason
	PathList    []*table.Path
	timestamp   time.Time
	payload     []byte
}

type fsmOutgoingMsg struct {
	Paths        []*table.Path
	Notification *bgp.BGPMessage
	StayIdle     bool
}

const (
	holdtimeOpensent = 240
	holdtimeIdle     = 5
)

type adminState int

const (
	adminStateUp adminState = iota
	adminStateDown
	adminStatePfxCt
)

func (s adminState) String() string {
	switch s {
	case adminStateUp:
		return "adminStateUp"
	case adminStateDown:
		return "adminStateDown"
	case adminStatePfxCt:
		return "adminStatePfxCt"
	default:
		return "Unknown"
	}
}

type adminStateOperation struct {
	State         adminState
	Communication []byte
}

type fsm struct {
	gConf                *oc.Global
	pConf                *oc.Neighbor
	lock                 sync.RWMutex
	state                bgp.FSMState
	outgoingCh           *channels.InfiniteChannel
	reason               *fsmStateReason
	conn                 net.Conn
	connCh               chan net.Conn
	idleHoldTime         float64
	opensentHoldTime     float64
	adminState           adminState
	adminStateCh         chan adminStateOperation
	h                    *fsmHandler
	rfMap                map[bgp.Family]bgp.BGPAddPathMode
	capMap               map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface
	recvOpen             *bgp.BGPMessage
	peerInfo             *table.PeerInfo
	gracefulRestartTimer *time.Timer
	twoByteAsTrans       bool
	marshallingOptions   *bgp.MarshallingOption
	notification         chan *bgp.BGPMessage
	logger               log.Logger
	longLivedRunning     bool

	// not accessed by server and grpc goroutines
	active  *fsmHandler
	passive *fsmHandler

	shutdownWg *sync.WaitGroup
}

type handlerEvent struct {
	state  bgp.FSMState
	reason *fsmStateReason
}

func (fsm *fsm) activeState() bgp.FSMState {
	if fsm.active != nil {
		return fsm.active.state
	}
	return bgp.BGP_FSM_IDLE
}

func (fsm *fsm) passiveState() bgp.FSMState {
	if fsm.passive != nil {
		return fsm.passive.state
	}
	if fsm.adminState == adminStateUp {
		return bgp.BGP_FSM_ACTIVE
	}
	return bgp.BGP_FSM_IDLE
}

func (fsm *fsm) changeState(reason *fsmStateReason, isActive bool, callback func(*fsmMsg)) {
	fsm.lock.RLock()
	oldState := fsm.state
	fsm.lock.RUnlock()

	var nextState bgp.FSMState
	if fsm.activeState() > fsm.passiveState() {
		nextState = fsm.activeState()
	} else {
		nextState = fsm.passiveState()
	}

	if nextState != oldState {
		fsm.lock.Lock()

		fsm.reason = reason

		if nextState == bgp.BGP_FSM_ESTABLISHED {
			fsm.logger.Info("Peer Up",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
				})
			fsm.gracefulRestartTimer.Stop()

			var handler *fsmHandler
			if isActive {
				handler = fsm.active
			} else {
				handler = fsm.passive
			}
			fsm.conn = handler.conn
			fsm.recvOpen = handler.recvOpen

			open := handler.recvOpen.Body.(*bgp.BGPOpen)

			fsm.pConf.State.PeerAs = handler.peerAS
			fsm.peerInfo.AS = handler.peerAS
			fsm.peerInfo.ID = open.ID
			fsm.capMap, fsm.rfMap = open2Cap(open, fsm.pConf)

			if _, y := fsm.capMap[bgp.BGP_CAP_ADD_PATH]; y {
				fsm.marshallingOptions = &bgp.MarshallingOption{
					AddPath: fsm.rfMap,
				}
			} else {
				fsm.marshallingOptions = nil
			}

			fsm.pConf.Timers.State.NegotiatedHoldTime = float64(handler.holdtime)

			myHoldTime := fsm.pConf.Timers.Config.HoldTime
			keepalive := fsm.pConf.Timers.Config.KeepaliveInterval
			if n := fsm.pConf.Timers.State.NegotiatedHoldTime; n < myHoldTime {
				keepalive = n / 3
			}
			fsm.pConf.Timers.State.KeepaliveInterval = keepalive

			gr, ok := fsm.capMap[bgp.BGP_CAP_GRACEFUL_RESTART]
			if fsm.pConf.GracefulRestart.Config.Enabled && ok {
				state := &fsm.pConf.GracefulRestart.State
				state.Enabled = true
				cap := gr[len(gr)-1].(*bgp.CapGracefulRestart)
				state.PeerRestartTime = cap.Time

				for _, t := range cap.Tuples {
					n := bgp.AddressFamilyNameMap[bgp.NewFamily(t.AFI, t.SAFI)]
					for i, a := range fsm.pConf.AfiSafis {
						if string(a.Config.AfiSafiName) == n {
							fsm.pConf.AfiSafis[i].MpGracefulRestart.State.Enabled = true
							fsm.pConf.AfiSafis[i].MpGracefulRestart.State.Received = true
							break
						}
					}
				}

				// RFC 4724 4.1
				// To re-establish the session with its peer, the Restarting Speaker
				// MUST set the "Restart State" bit in the Graceful Restart Capability
				// of the OPEN message.
				if fsm.pConf.GracefulRestart.State.PeerRestarting && cap.Flags&0x08 == 0 {
					fsm.logger.Warn("restart flag is not set",
						log.Fields{
							"Topic": "Peer",
							"Key":   fsm.pConf.State.NeighborAddress,
							"State": fsm.state.String(),
						})
					// just ignore
				}

				// RFC 4724 3
				// The most significant bit is defined as the Restart State (R)
				// bit, ...(snip)... When set (value 1), this bit
				// indicates that the BGP speaker has restarted, and its peer MUST
				// NOT wait for the End-of-RIB marker from the speaker before
				// advertising routing information to the speaker.
				if fsm.pConf.GracefulRestart.State.LocalRestarting && cap.Flags&0x08 != 0 {
					fsm.logger.Debug("peer has restarted, skipping wait for EOR",
						log.Fields{
							"Topic": "Peer",
							"Key":   fsm.pConf.State.NeighborAddress,
							"State": fsm.state.String(),
						})
					for i := range fsm.pConf.AfiSafis {
						fsm.pConf.AfiSafis[i].MpGracefulRestart.State.EndOfRibReceived = true
					}
				}
				if fsm.pConf.GracefulRestart.Config.NotificationEnabled && cap.Flags&0x04 > 0 {
					fsm.pConf.GracefulRestart.State.NotificationEnabled = true
				}
			}
			llgr, ok2 := fsm.capMap[bgp.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART]
			if fsm.pConf.GracefulRestart.Config.LongLivedEnabled && ok && ok2 {
				fsm.pConf.GracefulRestart.State.LongLivedEnabled = true
				cap := llgr[len(llgr)-1].(*bgp.CapLongLivedGracefulRestart)
				for _, t := range cap.Tuples {
					n := bgp.AddressFamilyNameMap[bgp.NewFamily(t.AFI, t.SAFI)]
					for i, a := range fsm.pConf.AfiSafis {
						if string(a.Config.AfiSafiName) == n {
							fsm.pConf.AfiSafis[i].LongLivedGracefulRestart.State.Enabled = true
							fsm.pConf.AfiSafis[i].LongLivedGracefulRestart.State.Received = true
							fsm.pConf.AfiSafis[i].LongLivedGracefulRestart.State.PeerRestartTime = t.RestartTime
							break
						}
					}
				}
			}
		}

		if oldState == bgp.BGP_FSM_ESTABLISHED {
			// // The server/grpc goroutines sent the notification due to
			// // deconfiguration or something.
			// if fsm.h.sentNotification != nil {
			// 	reason.Type = fsmNotificationSent
			// 	reason.BGPNotification = fsm.h.sentNotification
			// }
			fsm.logger.Info("Peer Down",
				log.Fields{
					"Topic":  "Peer",
					"Key":    fsm.pConf.State.NeighborAddress,
					"State":  fsm.state.String(),
					"Reason": reason.String(),
				})
			fsm.conn = nil

			if s := fsm.pConf.GracefulRestart.State; s.Enabled {
				if (s.NotificationEnabled && reason.Type == fsmNotificationRecv) ||
					(reason.Type == fsmNotificationSent &&
						reason.BGPNotification.Body.(*bgp.BGPNotification).ErrorCode == bgp.BGP_ERROR_HOLD_TIMER_EXPIRED) ||
					reason.Type == fsmReadFailed ||
					reason.Type == fsmWriteFailed {
					reason = newfsmStateReason(fsmGracefulRestart, nil, nil)
					fsm.logger.Info("peer graceful restart",
						log.Fields{
							"Topic": "Peer",
							"Key":   fsm.pConf.State.NeighborAddress,
							"State": fsm.state.String()})
					fsm.gracefulRestartTimer.Reset(time.Duration(fsm.pConf.GracefulRestart.State.PeerRestartTime) * time.Second)
				}
			}
		}

		msg := &fsmMsg{
			MsgType:     fsmMsgStateChange,
			MsgSrc:      fsm.pConf.State.NeighborAddress,
			MsgData:     nextState,
			StateReason: reason,
		}
		fsm.lock.Unlock()

		callback(msg)
	}
}

func (h *fsmHandler) sendNotification(code uint8, subcode uint8, data []byte) {
	// we should use context but we just send a notification. Even if it fails, no big deal.
	// So we set a arbitrary deadline.
	m := bgp.NewBGPNotificationMessage(code, subcode, nil)
	buf, _ := m.Serialize()
	h.conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	h.conn.Write(buf)
}

// This function exits in the following two cases:
// - When the context is canceled (e.g., the peer configuration is removed)
// - When the dynamic neighbor transitions to the idle state (TODO: handle graceful restart case)
func (fsm *fsm) Serve(ctx context.Context, wg *sync.WaitGroup, callback func(*fsmMsg)) {
	stopHandlers := func() {
		if fsm.active != nil {
			fsm.active.stop()
			fsm.active = nil
		}
		if fsm.passive != nil {
			fsm.passive.stop()
			fsm.passive = nil
		}

	}

	wg.Add(1)
	defer wg.Done()

	activeEventCh := make(chan handlerEvent)
	passiveEventCh := make(chan handlerEvent)

	fmt.Println("fsm serve")
	for {
		fsm.lock.RLock()
		state := fsm.state
		adminState := fsm.adminState
		fsm.lock.RUnlock()

		// Do not initiate an active connection if the passive connection is already
		// in OpenConfirm or Established state.
		// This is because, once one FSM reaches OpenConfirm, the other FSM—if it is still
		// in a state prior to OpenConfirm—will be stopped.
		if fsm.active == nil && state < bgp.BGP_FSM_OPENCONFIRM && adminState == adminStateUp && !fsm.pConf.Transport.Config.PassiveMode {
			fsm.active = newFSMHandler(fsm, bgp.BGP_FSM_CONNECT, callback, activeEventCh, nil)
			fsm.active.start()
		}

		select {
		case <-ctx.Done():
			stopHandlers()

			// Close passive connection.
			select {
			case conn := <-fsm.connCh:
				conn.Close()
			default:
			}

			// FSM has been already stopped. No need to lock it.
			if fsm.state == bgp.BGP_FSM_ESTABLISHED {
				select {
				case notification := <-fsm.notification:
					buf, _ := notification.Serialize()
					// context is already cancelled. If write is struck, nothing will cancel it.
					// so we set a deadline.
					fsm.conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
					fsm.conn.Write(buf)
				default:
				}
			}

			cleanInfiniteChannel(fsm.outgoingCh)
			return
		case stateOp := <-fsm.adminStateCh:
			err := fsm.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case adminStateDown:
					stopHandlers()
					fsm.changeState(newfsmStateReason(fsmAdminDown, nil, nil), true, callback)
				}
			}
		case <-fsm.gracefulRestartTimer.C:
			fsm.lock.RLock()
			restarting := fsm.pConf.GracefulRestart.State.PeerRestarting
			fsm.lock.RUnlock()

			if restarting {
				fsm.lock.RLock()
				fsm.logger.Warn("graceful restart timer expired",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.pConf.State.NeighborAddress,
						"State": fsm.state.String(),
					})
				fsm.lock.RUnlock()

				stopHandlers()
				fsm.changeState(newfsmStateReason(fsmRestartTimerExpired, nil, nil), true, callback)
			}

		case conn := <-fsm.connCh:
			fmt.Println("new connection received")
			if fsm.active != nil {
				conn.Close()
			} else if adminState == adminStateUp {
				fsm.passive = newFSMHandler(fsm, bgp.BGP_FSM_OPENSENT, callback, passiveEventCh, conn)
				fsm.passive.start()
			}
		case event := <-activeEventCh:
			fmt.Println("active event received", event.state.String())
			callchangeState := true
			// handler is stopped so no race; we can safely update the state.
			fsm.active.state = event.state
			fsm.logger.Info("Active State",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": event.state.String(),
				})
			switch event.state {
			case bgp.BGP_FSM_IDLE:
				// close the old connection if it exists. the active FSM will try to connect again.
				if fsm.active.conn != nil {
					fsm.active.conn.Close()
					fsm.active.conn = nil
				}
			case bgp.BGP_FSM_OPENCONFIRM:
				switch fsm.passiveState() {
				case bgp.BGP_FSM_OPENCONFIRM:
					callchangeState = false
					myid := binary.BigEndian.Uint32(net.ParseIP(fsm.gConf.Config.RouterId).To4())
					if myid < fsm.active.routerID || (myid == fsm.active.routerID && fsm.pConf.Config.LocalAs < fsm.active.peerAS) {
						// The remote peer is dominant. so close our active fsm.
						// The active FSM is already stopped, so we can't call fsm.active.stop().
						fsm.active.sendNotification(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION, nil)
						fsm.active.conn.Close()
						fsm.active = nil
					} else {
						// we are dominant, so close our passive fsm.
						fsm.passive.stop()
						fsm.passive.sendNotification(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION, nil)
						fsm.passive.conn.Close()
						fsm.passive = nil
					}
				}
			}

			if callchangeState {
				fsm.changeState(event.reason, true, callback)
			}
			if fsm.active != nil {
				fsm.active.start()
			}
		case event := <-passiveEventCh:
			callchangeState := true
			// handler is stopped so no race; we can safely update the state.
			fsm.passive.state = event.state
			fmt.Println("passive event received", event.state.String())
			switch event.state {
			case bgp.BGP_FSM_IDLE:
				fsm.passive.conn.Close()
				fsm.passive = nil
			case bgp.BGP_FSM_OPENCONFIRM:
				switch fsm.activeState() {
				case bgp.BGP_FSM_CONNECT:
					// stop the active FSM to try to connect.
					fsm.active.stop()
					fsm.active.conn.Close()
					fsm.active = nil
				case bgp.BGP_FSM_OPENCONFIRM:
					callchangeState = false
					myid := binary.BigEndian.Uint32(net.ParseIP(fsm.gConf.Config.RouterId).To4())
					if myid < fsm.active.routerID || (myid == fsm.active.routerID && fsm.pConf.Config.LocalAs < fsm.active.peerAS) {
						// the remote peer is dominant. so close our active fsm.
						fsm.active.stop()
						fsm.active.sendNotification(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION, nil)
						fsm.active.conn.Close()
						fsm.active = nil
					} else {
						// we are dominant, so close our passive fsm.
						// The passive FSM is already stopped, so we can't call fsm.passive.stop().
						fsm.passive.sendNotification(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION, nil)
						fsm.passive.conn.Close()
						fsm.passive = nil
					}
				}
			}

			if callchangeState {
				fsm.changeState(event.reason, false, callback)
			}
			if fsm.passive != nil {
				fsm.passive.start()
			}
		}
	}
}

func (fsm *fsm) bgpMessageStateUpdate(MessageType uint8, isIn bool) {
	fsm.lock.Lock()
	defer fsm.lock.Unlock()
	state := &fsm.pConf.State.Messages
	timer := &fsm.pConf.Timers
	if isIn {
		state.Received.Total++
	} else {
		state.Sent.Total++
	}
	switch MessageType {
	case bgp.BGP_MSG_OPEN:
		if isIn {
			state.Received.Open++
		} else {
			state.Sent.Open++
		}
	case bgp.BGP_MSG_UPDATE:
		if isIn {
			state.Received.Update++
			timer.State.UpdateRecvTime = time.Now().Unix()
		} else {
			state.Sent.Update++
		}
	case bgp.BGP_MSG_NOTIFICATION:
		if isIn {
			state.Received.Notification++
		} else {
			state.Sent.Notification++
		}
	case bgp.BGP_MSG_KEEPALIVE:
		if isIn {
			state.Received.Keepalive++
		} else {
			state.Sent.Keepalive++
		}
	case bgp.BGP_MSG_ROUTE_REFRESH:
		if isIn {
			state.Received.Refresh++
		} else {
			state.Sent.Refresh++
		}
	default:
		if isIn {
			state.Received.Discarded++
		} else {
			state.Sent.Discarded++
		}
	}
}

func (fsm *fsm) bmpStatsUpdate(statType uint16, increment int) {
	fsm.lock.Lock()
	defer fsm.lock.Unlock()
	stats := &fsm.pConf.State.Messages.Received
	switch statType {
	// TODO
	// Support other stat types.
	case bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE:
		stats.WithdrawUpdate += uint32(increment)
	case bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX:
		stats.WithdrawPrefix += uint32(increment)
	}
}

func newFSM(gConf *oc.Global, pConf *oc.Neighbor, logger log.Logger) *fsm {
	adminState := adminStateUp
	if pConf.Config.AdminDown {
		adminState = adminStateDown
	}
	pConf.State.SessionState = oc.IntToSessionStateMap[int(bgp.BGP_FSM_IDLE)]
	pConf.Timers.State.Downtime = time.Now().Unix()
	fsm := &fsm{
		gConf:                gConf,
		pConf:                pConf,
		state:                bgp.BGP_FSM_IDLE,
		outgoingCh:           channels.NewInfiniteChannel(),
		connCh:               make(chan net.Conn, 1),
		opensentHoldTime:     float64(holdtimeOpensent),
		adminState:           adminState,
		adminStateCh:         make(chan adminStateOperation, 1),
		rfMap:                make(map[bgp.Family]bgp.BGPAddPathMode),
		capMap:               make(map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface),
		peerInfo:             table.NewPeerInfo(gConf, pConf),
		gracefulRestartTimer: time.NewTimer(time.Hour),
		notification:         make(chan *bgp.BGPMessage, 1),
		logger:               logger,
	}
	fsm.gracefulRestartTimer.Stop()
	return fsm
}

// called by server.go
func (fsm *fsm) StateChange(nextState bgp.FSMState) {
	fsm.lock.Lock()
	defer fsm.lock.Unlock()

	fsm.logger.Debug("state changed",
		log.Fields{
			"Topic":  "Peer",
			"Key":    fsm.pConf.State.NeighborAddress,
			"old":    fsm.state.String(),
			"new":    nextState.String(),
			"reason": fsm.reason,
		})
	fsm.state = nextState
	switch nextState {
	case bgp.BGP_FSM_ESTABLISHED:
		fsm.pConf.Timers.State.Uptime = time.Now().Unix()
		fsm.pConf.State.EstablishedCount++
		// reset the state set by the previous session
		fsm.twoByteAsTrans = false
		if _, y := fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]; !y {
			fsm.twoByteAsTrans = true
			break
		}
		y := func() bool {
			for _, c := range capabilitiesFromConfig(fsm.pConf) {
				switch c.(type) {
				case *bgp.CapFourOctetASNumber:
					return true
				}
			}
			return false
		}()
		if !y {
			fsm.twoByteAsTrans = true
		}
	default:
		fsm.pConf.Timers.State.Downtime = time.Now().Unix()
	}
}

func hostport(addr net.Addr) (string, uint16) {
	if addr != nil {
		host, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			return "", 0
		}
		p, _ := strconv.ParseUint(port, 10, 16)
		return host, uint16(p)
	}
	return "", 0
}

func (fsm *fsm) RemoteHostPort() (string, uint16) {
	return hostport(fsm.conn.RemoteAddr())
}

func (fsm *fsm) LocalHostPort() (string, uint16) {
	return hostport(fsm.conn.LocalAddr())
}

type fsmHandler struct {
	fsm              *fsm
	state            bgp.FSMState
	conn             net.Conn
	sentNotification *bgp.BGPMessage

	recvOpen *bgp.BGPMessage
	peerType oc.PeerType
	peerAS   uint32
	routerID uint32
	holdtime uint16

	ctx      context.Context
	cancel   context.CancelFunc
	callback func(*fsmMsg)
	eventCh  chan handlerEvent
}

func newFSMHandler(fsm *fsm, state bgp.FSMState, callback func(*fsmMsg), ch chan handlerEvent, conn net.Conn) *fsmHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &fsmHandler{
		fsm:      fsm,
		state:    state,
		conn:     conn,
		callback: callback,
		ctx:      ctx,
		cancel:   cancel,
		eventCh:  ch,
	}
}

func (h *fsmHandler) start() {
	switch h.state {
	case bgp.BGP_FSM_IDLE:
		go h.idleState()
	case bgp.BGP_FSM_ACTIVE:
		h.fsm.logger.Panic("we don't use active state handler",
			log.Fields{
				"Topic": "FSM",
				"State": h.fsm.state.String(),
			})
	case bgp.BGP_FSM_CONNECT:
		go h.connectState()
	case bgp.BGP_FSM_OPENSENT:
		go h.opensentState()
	case bgp.BGP_FSM_OPENCONFIRM:
		go h.openconfirmState()
	case bgp.BGP_FSM_ESTABLISHED:
		go h.establishedState()
	}
}

func (h *fsmHandler) stop() {
	h.cancel()
	<-h.eventCh
}

func (h *fsmHandler) idleState() {
	fmt.Println("idleState: start", h.fsm.idleHoldTime)
	h.fsm.lock.RLock()
	idleHoldTimer := time.NewTimer(time.Second * time.Duration(h.fsm.idleHoldTime))
	h.fsm.lock.RUnlock()

	for {
		select {
		case <-h.ctx.Done():
			h.eventCh <- handlerEvent{
				state:  bgp.BGP_FSM_IDLE,
				reason: newfsmStateReason(fsmDying, nil, nil),
			}
			return
		case <-idleHoldTimer.C:
			// we don't create IDLE state handler for passive.
			h.eventCh <- handlerEvent{
				state: bgp.BGP_FSM_CONNECT,
			}
			return
		}
	}
}

func (h *fsmHandler) connectState() {
	fmt.Println("connectState: start")
	fsm := h.fsm

	retryInterval, addr, port, password, ttl, ttlMin, mss, localAddress, localPort, bindInterface := func() (int, string, int, string, uint8, uint8, uint16, string, int, string) {
		fsm.lock.RLock()
		defer fsm.lock.RUnlock()

		tick := max(int(fsm.pConf.Timers.Config.ConnectRetry), minConnectRetryInterval)

		addr := fsm.pConf.State.NeighborAddress
		port := int(bgp.BGP_PORT)
		if fsm.pConf.Transport.Config.RemotePort != 0 {
			port = int(fsm.pConf.Transport.Config.RemotePort)
		}
		password := fsm.pConf.Config.AuthPassword
		ttl := uint8(0)
		ttlMin := uint8(0)

		if fsm.pConf.TtlSecurity.Config.Enabled {
			ttl = 255
			ttlMin = fsm.pConf.TtlSecurity.Config.TtlMin
		} else if fsm.pConf.Config.PeerAs != 0 && fsm.pConf.Config.PeerType == oc.PEER_TYPE_EXTERNAL {
			ttl = 1
			if fsm.pConf.EbgpMultihop.Config.Enabled {
				ttl = fsm.pConf.EbgpMultihop.Config.MultihopTtl
			}
		}
		return tick, addr, port, password, ttl, ttlMin, fsm.pConf.Transport.Config.TcpMss, fsm.pConf.Transport.Config.LocalAddress, int(fsm.pConf.Transport.Config.LocalPort), fsm.pConf.Transport.Config.BindInterface
	}()

	retryCounter := 0
	for {
		// Add random jitter (0-2 seconds) before initial active connection attempt
		// to avoid thundering herd problem when multiple BGP speakers start simultaneously.
		var delay float64
		if retryCounter == 0 {
			delay = rand.Float64() * 2
		} else {
			delay = float64(retryInterval)
		}
		timer := time.NewTimer(time.Duration(delay) * time.Second)
		select {
		case <-h.ctx.Done():
			h.eventCh <- handlerEvent{
				state:  bgp.BGP_FSM_IDLE,
				reason: newfsmStateReason(fsmDying, nil, nil),
			}
			return
		case <-timer.C:
			if fsm.logger.GetLevel() >= log.DebugLevel {
				fsm.logger.Debug("try to connect",
					log.Fields{
						"Topic": "Peer",
						"Key":   addr,
					})
			}
		}

		laddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(localAddress, strconv.Itoa(localPort)))
		if err != nil {
			fsm.logger.Warn("failed to resolve local address",
				log.Fields{
					"Topic": "Peer",
					"Key":   addr,
				})
		}

		if err == nil {
			d := net.Dialer{
				LocalAddr: laddr,
				Timeout:   time.Duration(retryInterval) * time.Second,
				KeepAlive: -1,
				Control: func(network, address string, c syscall.RawConn) error {
					return netutils.DialerControl(fsm.logger, network, address, c, ttl, ttlMin, mss, password, bindInterface)
				},
			}

			conn, err := d.DialContext(h.ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
			select {
			case <-h.ctx.Done():
				fsm.logger.Debug("stop connect loop",
					log.Fields{
						"Topic": "Peer",
						"Key":   addr,
					})
				h.eventCh <- handlerEvent{
					state:  bgp.BGP_FSM_IDLE,
					reason: newfsmStateReason(fsmDying, nil, nil),
				}
				return
			default:
			}

			if err == nil {
				h.conn = conn
				h.eventCh <- handlerEvent{
					state: bgp.BGP_FSM_OPENSENT}
				return
			} else {
				if fsm.logger.GetLevel() >= log.DebugLevel {
					fsm.logger.Debug("failed to connect",
						log.Fields{
							"Topic": "Peer",
							"Key":   addr,
							"Error": err,
						})
				}
			}
		}
		retryCounter++
	}
}

func setPeerConnTTL(fsm *fsm) error {
	ttl := 0
	ttlMin := 0

	if fsm.pConf.TtlSecurity.Config.Enabled {
		ttl = 255
		ttlMin = int(fsm.pConf.TtlSecurity.Config.TtlMin)
	} else if fsm.pConf.Config.PeerAs != 0 && fsm.pConf.Config.PeerType == oc.PEER_TYPE_EXTERNAL {
		if fsm.pConf.EbgpMultihop.Config.Enabled {
			ttl = int(fsm.pConf.EbgpMultihop.Config.MultihopTtl)
		} else if fsm.pConf.Transport.Config.Ttl != 0 {
			ttl = int(fsm.pConf.Transport.Config.Ttl)
		} else {
			ttl = 1
		}
	} else if fsm.pConf.Transport.Config.Ttl != 0 {
		ttl = int(fsm.pConf.Transport.Config.Ttl)
	}

	if ttl != 0 {
		if err := netutils.SetTCPTTLSockopt(fsm.conn, ttl); err != nil {
			return fmt.Errorf("failed to set TTL %d: %w", ttl, err)
		}
	}
	if ttlMin != 0 {
		if err := netutils.SetTCPMinTTLSockopt(fsm.conn, ttlMin); err != nil {
			return fmt.Errorf("failed to set minimal TTL %d: %w", ttlMin, err)
		}
	}
	return nil
}

func setPeerConnMSS(fsm *fsm) error {
	mss := fsm.pConf.Transport.Config.TcpMss
	if mss == 0 {
		return nil
	}
	if err := netutils.SetTCPMSSSockopt(fsm.conn, mss); err != nil {
		return fmt.Errorf("failed to set MSS %d: %w", mss, err)
	}
	return nil
}

func capAddPathFromConfig(pConf *oc.Neighbor) bgp.ParameterCapabilityInterface {
	tuples := make([]*bgp.CapAddPathTuple, 0, len(pConf.AfiSafis))
	for _, af := range pConf.AfiSafis {
		var mode bgp.BGPAddPathMode
		if af.AddPaths.State.Receive {
			mode |= bgp.BGP_ADD_PATH_RECEIVE
		}
		if af.AddPaths.State.SendMax > 0 {
			mode |= bgp.BGP_ADD_PATH_SEND
		}
		if mode > 0 {
			tuples = append(tuples, bgp.NewCapAddPathTuple(af.State.Family, mode))
		}
	}
	if len(tuples) == 0 {
		return nil
	}
	return bgp.NewCapAddPath(tuples)
}

func capabilitiesFromConfig(pConf *oc.Neighbor) []bgp.ParameterCapabilityInterface {
	fqdn, _ := os.Hostname()
	caps := make([]bgp.ParameterCapabilityInterface, 0, 4)
	caps = append(caps, bgp.NewCapRouteRefresh())
	caps = append(caps, bgp.NewCapFQDN(fqdn, ""))

	if pConf.Config.SendSoftwareVersion || pConf.Config.PeerType == oc.PEER_TYPE_INTERNAL {
		softwareVersion := fmt.Sprintf("GoBGP/%s", version.Version())
		caps = append(caps, bgp.NewCapSoftwareVersion(softwareVersion))
	}

	for _, af := range pConf.AfiSafis {
		caps = append(caps, bgp.NewCapMultiProtocol(af.State.Family))
	}
	caps = append(caps, bgp.NewCapFourOctetASNumber(pConf.Config.LocalAs))

	if c := pConf.GracefulRestart.Config; c.Enabled {
		tuples := []*bgp.CapGracefulRestartTuple{}
		ltuples := []*bgp.CapLongLivedGracefulRestartTuple{}

		// RFC 4724 4.1
		// To re-establish the session with its peer, the Restarting Speaker
		// MUST set the "Restart State" bit in the Graceful Restart Capability
		// of the OPEN message.
		restarting := pConf.GracefulRestart.State.LocalRestarting

		if !c.HelperOnly {
			for i, rf := range pConf.AfiSafis {
				if m := rf.MpGracefulRestart.Config; m.Enabled {
					// When restarting, always flag forwaring bit.
					// This can be a lie, depending on how gobgpd is used.
					// For a route-server use-case, since a route-server
					// itself doesn't forward packets, and the dataplane
					// is a l2 switch which continues to work with no
					// relation to bgpd, this behavior is ok.
					// TODO consideration of other use-cases
					tuples = append(tuples, bgp.NewCapGracefulRestartTuple(rf.State.Family, restarting))
					pConf.AfiSafis[i].MpGracefulRestart.State.Advertised = true
				}
				if m := rf.LongLivedGracefulRestart.Config; m.Enabled {
					ltuples = append(ltuples, bgp.NewCapLongLivedGracefulRestartTuple(rf.State.Family, restarting, m.RestartTime))
				}
			}
		}
		restartTime := c.RestartTime
		notification := c.NotificationEnabled
		caps = append(caps, bgp.NewCapGracefulRestart(restarting, notification, restartTime, tuples))
		if c.LongLivedEnabled {
			caps = append(caps, bgp.NewCapLongLivedGracefulRestart(ltuples))
		}
	}

	// Extended Nexthop Capability (Code 5)
	tuples := []*bgp.CapExtendedNexthopTuple{}
	families, _ := oc.AfiSafis(pConf.AfiSafis).ToRfList()
	for _, family := range families {
		if family == bgp.RF_IPv6_UC {
			continue
		}
		tuple := bgp.NewCapExtendedNexthopTuple(family, bgp.AFI_IP6)
		tuples = append(tuples, tuple)
	}
	if len(tuples) != 0 {
		caps = append(caps, bgp.NewCapExtendedNexthop(tuples))
	}

	// ADD-PATH Capability
	if c := capAddPathFromConfig(pConf); c != nil {
		caps = append(caps, capAddPathFromConfig(pConf))
	}

	return caps
}

func buildopen(gConf *oc.Global, pConf *oc.Neighbor) *bgp.BGPMessage {
	caps := capabilitiesFromConfig(pConf)
	opt := bgp.NewOptionParameterCapability(caps)
	holdTime := uint16(pConf.Timers.Config.HoldTime)
	as := pConf.Config.LocalAs
	if as > 1<<16-1 {
		as = bgp.AS_TRANS
	}
	return bgp.NewBGPOpenMessage(uint16(as), holdTime, gConf.Config.RouterId,
		[]bgp.OptionParameterInterface{opt})
}

func readAll(conn net.Conn, length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func getPathAttrFromBGPUpdate(m *bgp.BGPUpdate, typ bgp.BGPAttrType) bgp.PathAttributeInterface {
	for _, a := range m.PathAttributes {
		if a.GetType() == typ {
			return a
		}
	}
	return nil
}

func hasOwnASLoop(ownAS uint32, limit int, asPath *bgp.PathAttributeAsPath) bool {
	cnt := 0
	for _, param := range asPath.Value {
		for _, as := range param.GetAS() {
			if as == ownAS {
				cnt++
				if cnt > limit {
					return true
				}
			}
		}
	}
	return false
}

func extractFamily(p *bgp.PathAttributeInterface) *bgp.Family {
	attr := *p

	var afi uint16
	var safi uint8

	switch a := attr.(type) {
	case *bgp.PathAttributeMpReachNLRI:
		afi = a.AFI
		safi = a.SAFI
	case *bgp.PathAttributeMpUnreachNLRI:
		afi = a.AFI
		safi = a.SAFI
	default:
		return nil
	}

	rf := bgp.NewFamily(afi, safi)
	return &rf
}

func (h *fsmHandler) afiSafiDisable(rf bgp.Family) string {
	h.fsm.lock.Lock()
	defer h.fsm.lock.Unlock()

	n := bgp.AddressFamilyNameMap[rf]

	for i, a := range h.fsm.pConf.AfiSafis {
		if string(a.Config.AfiSafiName) == n {
			h.fsm.pConf.AfiSafis[i].State.Enabled = false
			break
		}
	}
	newList := make([]bgp.ParameterCapabilityInterface, 0)
	for _, c := range h.fsm.capMap[bgp.BGP_CAP_MULTIPROTOCOL] {
		if c.(*bgp.CapMultiProtocol).CapValue == rf {
			continue
		}
		newList = append(newList, c)
	}
	h.fsm.capMap[bgp.BGP_CAP_MULTIPROTOCOL] = newList
	return n
}

func (h *fsmHandler) handlingError(m *bgp.BGPMessage, e error, useRevisedError bool) bgp.ErrorHandling {
	// ineffectual assignment to handling (ineffassign)
	var handling bgp.ErrorHandling
	if m.Header.Type == bgp.BGP_MSG_UPDATE && useRevisedError {
		factor := e.(*bgp.MessageError)
		handling = factor.ErrorHandling
		switch handling {
		case bgp.ERROR_HANDLING_ATTRIBUTE_DISCARD:
			h.fsm.lock.RLock()
			h.fsm.logger.Warn("Some attributes were discarded",
				log.Fields{
					"Topic": "Peer",
					"Key":   h.fsm.pConf.State.NeighborAddress,
					"State": h.fsm.state.String(),
					"Error": e,
				})
			h.fsm.lock.RUnlock()
		case bgp.ERROR_HANDLING_TREAT_AS_WITHDRAW:
			m.Body = bgp.TreatAsWithdraw(m.Body.(*bgp.BGPUpdate))
			h.fsm.lock.RLock()
			h.fsm.logger.Warn("the received Update message was treated as withdraw",
				log.Fields{
					"Topic": "Peer",
					"Key":   h.fsm.pConf.State.NeighborAddress,
					"State": h.fsm.state.String(),
					"Error": e,
				})
			h.fsm.lock.RUnlock()
		case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
			rf := extractFamily(factor.ErrorAttribute)
			if rf == nil {
				h.fsm.lock.RLock()
				h.fsm.logger.Warn("Error occurred during AFI/SAFI disabling",
					log.Fields{
						"Topic": "Peer",
						"Key":   h.fsm.pConf.State.NeighborAddress,
						"State": h.fsm.state.String(),
					})
				h.fsm.lock.RUnlock()
			} else {
				n := h.afiSafiDisable(*rf)
				h.fsm.lock.RLock()
				h.fsm.logger.Warn("Capability was disabled",
					log.Fields{
						"Topic": "Peer",
						"Key":   h.fsm.pConf.State.NeighborAddress,
						"State": h.fsm.state.String(),
						"Error": e,
						"Cap":   n,
					})
				h.fsm.lock.RUnlock()
			}
		}
	} else {
		handling = bgp.ERROR_HANDLING_SESSION_RESET
	}
	return handling
}

func (h *fsmHandler) recvMessageWithError() (*fsmMsg, error) {
	headerBuf, err := readAll(h.conn, bgp.BGP_HEADER_LENGTH)
	if err != nil {
		return &fsmMsg{StateReason: newfsmStateReason(fsmReadFailed, nil, nil)}, err
	}

	hd := &bgp.BGPHeader{}
	err = hd.DecodeFromBytes(headerBuf)
	if err != nil {
		h.fsm.bgpMessageStateUpdate(0, true)
		h.fsm.lock.RLock()
		h.fsm.logger.Warn("Session will be reset due to malformed BGP Header",
			log.Fields{
				"Topic": "Peer",
				"Key":   h.fsm.pConf.State.NeighborAddress,
				"State": h.fsm.state.String(),
				"Error": err,
			})
		fmsg := &fsmMsg{
			MsgType:     fsmMsgBGPMessage,
			MsgSrc:      h.fsm.pConf.State.NeighborAddress,
			MsgData:     err,
			StateReason: newfsmStateReason(fsmInvalidMsg, nil, nil),
		}
		h.fsm.lock.RUnlock()
		return fmsg, err
	}

	bodyBuf, err := readAll(h.conn, int(hd.Len)-bgp.BGP_HEADER_LENGTH)
	if err != nil {
		return &fsmMsg{StateReason: newfsmStateReason(fsmReadFailed, nil, nil)}, err
	}

	now := time.Now()
	handling := bgp.ERROR_HANDLING_NONE

	h.fsm.lock.RLock()
	useRevisedError := h.fsm.pConf.ErrorHandling.Config.TreatAsWithdraw
	options := h.fsm.marshallingOptions
	h.fsm.lock.RUnlock()

	m, err := bgp.ParseBGPBody(hd, bodyBuf, options)
	if err != nil {
		handling = h.handlingError(m, err, useRevisedError)
		h.fsm.bgpMessageStateUpdate(0, true)
	} else {
		h.fsm.bgpMessageStateUpdate(m.Header.Type, true)
		err = bgp.ValidateBGPMessage(m)
	}
	h.fsm.lock.RLock()
	fmsg := &fsmMsg{
		MsgType:   fsmMsgBGPMessage,
		MsgSrc:    h.fsm.pConf.State.NeighborAddress,
		timestamp: now,
	}
	h.fsm.lock.RUnlock()

	switch handling {
	case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
		fmsg.MsgData = m
		fmsg.StateReason = newfsmStateReason(fsmInvalidMsg, m, nil)
		return fmsg, err
	case bgp.ERROR_HANDLING_SESSION_RESET:
		h.fsm.lock.RLock()
		h.fsm.logger.Warn("Session will be reset due to malformed BGP message",
			log.Fields{
				"Topic": "Peer",
				"Key":   h.fsm.pConf.State.NeighborAddress,
				"State": h.fsm.state.String(),
				"Error": err,
			})
		h.fsm.lock.RUnlock()
		fmsg.StateReason = newfsmStateReason(fsmInvalidMsg, m, nil)
		fmsg.MsgData = err
		return fmsg, err
	default:
		fmsg.MsgData = m

		h.fsm.lock.RLock()
		establishedState := h.fsm.state == bgp.BGP_FSM_ESTABLISHED
		h.fsm.lock.RUnlock()

		if establishedState {
			switch m.Header.Type {
			case bgp.BGP_MSG_ROUTE_REFRESH:
				fmsg.MsgType = fsmMsgRouteRefresh
			case bgp.BGP_MSG_UPDATE:
				// if the length of h.holdTimerResetCh
				// isn't zero, the timer will be reset
				// soon anyway.
				body := m.Body.(*bgp.BGPUpdate)
				isEBGP := h.fsm.pConf.IsEBGPPeer(h.fsm.gConf)
				isConfed := h.fsm.pConf.IsConfederationMember(h.fsm.gConf)

				fmsg.payload = make([]byte, len(headerBuf)+len(bodyBuf))
				copy(fmsg.payload, headerBuf)
				copy(fmsg.payload[len(headerBuf):], bodyBuf)

				h.fsm.lock.RLock()
				rfMap := h.fsm.rfMap
				h.fsm.lock.RUnlock()

				// Allow updates from host loopback addresses if the BGP connection
				// with the neighbour is both dialed and received on loopback
				// addresses.
				var allowLoopback bool
				if localAddr, peerAddr := h.fsm.peerInfo.LocalAddress, h.fsm.peerInfo.Address; localAddr.To4() != nil && peerAddr.To4() != nil {
					allowLoopback = localAddr.IsLoopback() && peerAddr.IsLoopback()
				}
				ok, err := bgp.ValidateUpdateMsg(body, rfMap, isEBGP, isConfed, allowLoopback)
				if !ok {
					handling = h.handlingError(m, err, useRevisedError)
				}
				if handling == bgp.ERROR_HANDLING_SESSION_RESET {
					h.fsm.lock.RLock()
					h.fsm.logger.Warn("Session will be reset due to malformed BGP update message",
						log.Fields{
							"Topic": "Peer",
							"Key":   h.fsm.pConf.State.NeighborAddress,
							"State": h.fsm.state.String(),
							"error": err,
						})
					h.fsm.lock.RUnlock()
					fmsg.MsgData = err
					fmsg.StateReason = newfsmStateReason(fsmInvalidMsg, m, nil)
					return fmsg, err
				}

				if routes := len(body.WithdrawnRoutes); routes > 0 {
					h.fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
					h.fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
				} else if attr := getPathAttrFromBGPUpdate(body, bgp.BGP_ATTR_TYPE_MP_UNREACH_NLRI); attr != nil {
					mpUnreach := attr.(*bgp.PathAttributeMpUnreachNLRI)
					if routes = len(mpUnreach.Value); routes > 0 {
						h.fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
						h.fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
					}
				}

				table.UpdatePathAttrs4ByteAs(h.fsm.logger, body)

				if err = table.UpdatePathAggregator4ByteAs(body); err != nil {
					fmsg.MsgData = err
					fmsg.StateReason = newfsmStateReason(fsmInvalidMsg, m, nil)
					return fmsg, err
				}

				h.fsm.lock.RLock()
				peerInfo := h.fsm.peerInfo
				h.fsm.lock.RUnlock()
				fmsg.PathList = table.ProcessMessage(m, peerInfo, fmsg.timestamp)
			case bgp.BGP_MSG_KEEPALIVE:
				// nothing to do
			case bgp.BGP_MSG_NOTIFICATION:
				body := m.Body.(*bgp.BGPNotification)
				if body.ErrorCode == bgp.BGP_ERROR_CEASE && (body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN || body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET) {
					communication, rest := decodeAdministrativeCommunication(body.Data)
					h.fsm.lock.RLock()
					h.fsm.logger.Warn("received notification",
						log.Fields{
							"Topic":               "Peer",
							"Key":                 h.fsm.pConf.State.NeighborAddress,
							"Code":                body.ErrorCode,
							"Subcode":             body.ErrorSubcode,
							"Communicated-Reason": communication,
							"Data":                rest,
						})
					h.fsm.lock.RUnlock()
				} else {
					h.fsm.lock.RLock()
					h.fsm.logger.Warn("received notification",
						log.Fields{
							"Topic":   "Peer",
							"Key":     h.fsm.pConf.State.NeighborAddress,
							"Code":    body.ErrorCode,
							"Subcode": body.ErrorSubcode,
							"Data":    body.Data,
						})
					h.fsm.lock.RUnlock()
				}

				h.fsm.lock.RLock()
				s := h.fsm.pConf.GracefulRestart.State
				hardReset := s.Enabled && s.NotificationEnabled && body.ErrorCode == bgp.BGP_ERROR_CEASE && body.ErrorSubcode == bgp.BGP_ERROR_SUB_HARD_RESET
				h.fsm.lock.RUnlock()

				if hardReset {
					fmsg.StateReason = newfsmStateReason(fsmHardReset, m, nil)
				} else {
					fmsg.StateReason = newfsmStateReason(fsmNotificationRecv, m, nil)
				}
				return fmsg, fmt.Errorf("received notification")
			}
		}
	}
	return fmsg, nil
}

func open2Cap(open *bgp.BGPOpen, n *oc.Neighbor) (map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface, map[bgp.Family]bgp.BGPAddPathMode) {
	capMap := make(map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface)
	for _, p := range open.OptParams {
		if paramCap, y := p.(*bgp.OptionParameterCapability); y {
			for _, c := range paramCap.Capability {
				m, ok := capMap[c.Code()]
				if !ok {
					m = make([]bgp.ParameterCapabilityInterface, 0, 1)
				}
				capMap[c.Code()] = append(m, c)
			}
		}
	}

	// squash add path cap
	if caps, y := capMap[bgp.BGP_CAP_ADD_PATH]; y {
		items := make([]*bgp.CapAddPathTuple, 0, len(caps))
		for _, c := range caps {
			items = append(items, c.(*bgp.CapAddPath).Tuples...)
		}
		capMap[bgp.BGP_CAP_ADD_PATH] = []bgp.ParameterCapabilityInterface{bgp.NewCapAddPath(items)}
	}

	// remote open message may not include multi-protocol capability
	if _, y := capMap[bgp.BGP_CAP_MULTIPROTOCOL]; !y {
		capMap[bgp.BGP_CAP_MULTIPROTOCOL] = []bgp.ParameterCapabilityInterface{bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC)}
	}

	local := n.CreateRfMap()
	remote := make(map[bgp.Family]bgp.BGPAddPathMode)
	for _, c := range capMap[bgp.BGP_CAP_MULTIPROTOCOL] {
		family := c.(*bgp.CapMultiProtocol).CapValue
		remote[family] = bgp.BGP_ADD_PATH_NONE
		for _, a := range capMap[bgp.BGP_CAP_ADD_PATH] {
			for _, i := range a.(*bgp.CapAddPath).Tuples {
				if i.Family == family {
					remote[family] = i.Mode
				}
			}
		}
	}
	negotiated := make(map[bgp.Family]bgp.BGPAddPathMode)
	for family, mode := range local {
		if m, y := remote[family]; y {
			n := bgp.BGP_ADD_PATH_NONE
			if mode&bgp.BGP_ADD_PATH_SEND > 0 && m&bgp.BGP_ADD_PATH_RECEIVE > 0 {
				n |= bgp.BGP_ADD_PATH_SEND
			}
			if mode&bgp.BGP_ADD_PATH_RECEIVE > 0 && m&bgp.BGP_ADD_PATH_SEND > 0 {
				n |= bgp.BGP_ADD_PATH_RECEIVE
			}
			negotiated[family] = n
		}
	}
	return capMap, negotiated
}

type recvResult struct {
	msg *fsmMsg
	err error
}

func (h *fsmHandler) opensentState() {
	fmt.Println("opensentState called")

	h.fsm.lock.Lock()
	m := buildopen(h.fsm.gConf, h.fsm.pConf)
	holdTimer := time.NewTimer(time.Second * time.Duration(h.fsm.opensentHoldTime))
	h.fsm.lock.Unlock()

	buf, _ := m.Serialize()
	errCh := make(chan error, 1)

	go func() {
		_, err := h.conn.Write(buf)
		errCh <- err
	}()

	select {
	case <-h.ctx.Done():
		h.conn.SetWriteDeadline(time.Now())
		// wait for an error
		<-errCh
		h.eventCh <- handlerEvent{
			state:  bgp.BGP_FSM_IDLE,
			reason: newfsmStateReason(fsmDying, nil, nil),
		}
		return
	case <-holdTimer.C:
		<-errCh
		h.eventCh <- handlerEvent{
			state:  bgp.BGP_FSM_IDLE,
			reason: newfsmStateReason(fsmHoldTimerExpired, nil, nil),
		}
		return
	case err := <-errCh:
		if err == nil {
			h.fsm.bgpMessageStateUpdate(m.Header.Type, false)
		} else {
			h.eventCh <- handlerEvent{
				state:  bgp.BGP_FSM_IDLE,
				reason: newfsmStateReason(fsmWriteFailed, nil, nil),
			}
			return
		}
	}

	fmt.Println("opensentState: waiting for Open message")

	recvCh := make(chan recvResult, 1)

	go func() {
		msg, err := h.recvMessageWithError()
		recvCh <- recvResult{
			msg: msg,
			err: err,
		}
	}()

	select {
	case <-h.ctx.Done():
		fmt.Println("opensentState: context done")
		h.conn.SetReadDeadline(time.Now())
		<-recvCh
		h.eventCh <- handlerEvent{
			state:  bgp.BGP_FSM_IDLE,
			reason: newfsmStateReason(fsmDying, nil, nil),
		}
		fmt.Println("opensentState: exiting due to context done")
		return
	case r := <-recvCh:
		fmt.Println("opensentState: received message")
		if r.err == nil {
			body := r.msg.MsgData.(*bgp.BGPMessage).Body
			switch body := body.(type) {
			case *bgp.BGPOpen:
				fsm := h.fsm
				fsm.lock.Lock()
				h.recvOpen = r.msg.MsgData.(*bgp.BGPMessage)
				fsm.lock.Unlock()

				fsm.lock.RLock()
				fsmPeerAS := fsm.pConf.Config.PeerAs
				fsm.lock.RUnlock()
				peerAs, err := bgp.ValidateOpenMsg(body, fsmPeerAS, fsm.peerInfo.LocalAS, net.ParseIP(fsm.gConf.Config.RouterId))
				if err != nil {
					//m, _ := fsm.sendNotificationFromErrorMsg(err.(*bgp.MessageError))
					//return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, m, nil)
					h.eventCh <- handlerEvent{
						state:  bgp.BGP_FSM_IDLE,
						reason: newfsmStateReason(fsmInvalidMsg, m, nil),
					}
					return
				}
				h.routerID = binary.BigEndian.Uint32(body.ID.To4())

				// ASN negotiation was skipped
				fsm.lock.RLock()
				asnNegotiationSkipped := fsm.pConf.Config.PeerAs == 0
				fsm.lock.RUnlock()
				if asnNegotiationSkipped {
					fsm.lock.Lock()
					typ := oc.PEER_TYPE_EXTERNAL
					if fsm.peerInfo.LocalAS == peerAs {
						typ = oc.PEER_TYPE_INTERNAL
					}
					h.peerType = typ
					fsm.logger.Info("skipped asn negotiation",
						log.Fields{
							"Topic":    "Peer",
							"Key":      fsm.pConf.State.NeighborAddress,
							"State":    fsm.state.String(),
							"Asn":      peerAs,
							"PeerType": typ,
						})
					fsm.lock.Unlock()
				} else {
					h.peerType = fsm.pConf.Config.PeerType
				}
				h.peerAS = peerAs

				// calculate HoldTime
				// RFC 4271 P.13
				// a BGP speaker MUST calculate the value of the Hold Timer
				// by using the smaller of its configured Hold Time and the Hold Time
				// received in the OPEN message.
				holdTime := float64(body.HoldTime)
				myHoldTime := fsm.pConf.Timers.Config.HoldTime
				if holdTime > myHoldTime {
					h.holdtime = uint16(myHoldTime)
				} else {
					h.holdtime = uint16(holdTime)
				}
			default:
				// send notification?
				//h.conn.Close()
				//return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, nil, nil)
				h.eventCh <- handlerEvent{
					state:  bgp.BGP_FSM_IDLE,
					reason: newfsmStateReason(fsmInvalidMsg, m, nil),
				}
				return
			}
		} else {
			h.eventCh <- handlerEvent{
				state:  bgp.BGP_FSM_IDLE,
				reason: r.msg.StateReason,
			}
			return
		}
	}
	fmt.Println("opensentState: sending KeepAlive message")
	// FIXME : use context
	msg := bgp.NewBGPKeepAliveMessage()
	b, _ := msg.Serialize()
	h.conn.Write(b)
	h.fsm.bgpMessageStateUpdate(msg.Header.Type, false)

	fmt.Println("opensentState: sending OpenConfirm event")
	h.eventCh <- handlerEvent{
		state: bgp.BGP_FSM_OPENCONFIRM,
	}
}

func (h *fsmHandler) openconfirmState() {
	fmt.Println("openconfirmState called")

	// TODO: holdtime

	recvCh := make(chan recvResult, 1)

	go func() {
		msg, err := h.recvMessageWithError()
		recvCh <- recvResult{
			msg: msg,
			err: err,
		}
	}()

	select {
	case <-h.ctx.Done():
		h.conn.SetReadDeadline(time.Now())
		<-recvCh
		h.eventCh <- handlerEvent{
			state:  bgp.BGP_FSM_IDLE,
			reason: newfsmStateReason(fsmDying, nil, nil),
		}
	case r := <-recvCh:
		if r.err == nil {
			body := r.msg.MsgData.(*bgp.BGPMessage).Body
			switch body.(type) {
			case *bgp.BGPKeepAlive:
				h.eventCh <- handlerEvent{
					state: bgp.BGP_FSM_ESTABLISHED,
				}
			default:
				h.eventCh <- handlerEvent{
					state: bgp.BGP_FSM_IDLE,
				}
			}
		} else {
			h.eventCh <- handlerEvent{
				state:  bgp.BGP_FSM_IDLE,
				reason: r.msg.StateReason,
			}
		}
	}
}

func (h *fsmHandler) establishedState() {
	sendCh := make(chan *fsmStateReason)
	fmt.Println("establishedState called")

	// sendloop needs to use context unlike recvloop because it coulb be blocked on the channel.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		reason := h.sendMessageloop(ctx)
		sendCh <- reason
	}()

	var lastRecv atomic.Int64
	lastRecv.Store(time.Now().Unix())
	recvCh := make(chan *fsmMsg)
	go func() {
		for {
			// holdtimer
			msg, err := h.recvMessageWithError()
			if err == nil {
				if msg.MsgType == fsmMsgBGPMessage {
					bgpMsg := msg.MsgData.(*bgp.BGPMessage)
					switch bgpMsg.Header.Type {
					case bgp.BGP_MSG_UPDATE:
						h.callback(msg)
						fallthrough
					case bgp.BGP_MSG_KEEPALIVE:
						fmt.Println("received KeepAlive message")
						lastRecv.Store(time.Now().Unix())
					}
				}
			} else {
				recvCh <- msg
				return
			}
		}
	}()

	var negotiatedHoldTime int64
	h.fsm.lock.RLock()
	negotiatedHoldTime = int64(h.fsm.pConf.Timers.State.NegotiatedHoldTime)
	h.fsm.lock.RUnlock()

	fmt.Println("holdtime", negotiatedHoldTime)

	var holdTimer *time.Timer
	if negotiatedHoldTime == 0 {
		holdTimer = &time.Timer{}
	} else {
		holdTimer = time.NewTimer(time.Second * time.Duration(negotiatedHoldTime))
	}

	for {
		select {
		case <-h.ctx.Done():
			fmt.Println("establishedState: context done")
			// kill writer.
			cancel()
			// kill sender and writer that wait on socket.
			h.conn.SetDeadline(time.Now())
			// wait for writeloop to finish.
			<-sendCh
			<-recvCh
			h.eventCh <- handlerEvent{
				state:  bgp.BGP_FSM_IDLE,
				reason: newfsmStateReason(fsmDying, nil, nil),
			}
			return
		case <-holdTimer.C:
			last := lastRecv.Load()
			now := time.Now().Unix()
			fmt.Println("hold timer expired", now-negotiatedHoldTime, last, now, negotiatedHoldTime, negotiatedHoldTime-(now-last))
			if now-negotiatedHoldTime < last {
				holdTimer.Reset(time.Second * time.Duration(negotiatedHoldTime-(now-last)))
			} else {
				h.fsm.lock.RLock()
				s := h.fsm.pConf.GracefulRestart.State
				h.fsm.lock.RUnlock()
				h.sendNotification(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil)

				// Do not return hold timer expired to server if graceful restart is enabled
				// Let it fallback to read/write error or fsmNotificationSent handled above
				// Reference: https://github.com/osrg/gobgp/issues/2174
				if !s.Enabled {
					cancel()
					h.conn.SetDeadline(time.Now())
					<-sendCh
					<-recvCh

					h.eventCh <- handlerEvent{
						state:  bgp.BGP_FSM_IDLE,
						reason: newfsmStateReason(fsmHoldTimerExpired, nil, nil),
					}
					return
				}
			}
		case reason := <-sendCh:
			fmt.Println("establishedState: send error")
			// send error happened.
			h.conn.SetDeadline(time.Now())
			<-recvCh
			h.eventCh <- handlerEvent{
				state:  bgp.BGP_FSM_IDLE,
				reason: reason,
			}
			return
		case msg := <-recvCh:
			fmt.Println("establishedState: received error")
			// recv error happened.
			cancel()
			h.conn.SetDeadline(time.Now())
			// wait for writeloop to finish.
			<-sendCh
			h.eventCh <- handlerEvent{
				state:  bgp.BGP_FSM_IDLE,
				reason: msg.StateReason,
			}
			return
		}
	}
}

func keepaliveTicker(fsm *fsm) *time.Ticker {
	fsm.lock.RLock()
	defer fsm.lock.RUnlock()

	negotiatedTime := fsm.pConf.Timers.State.NegotiatedHoldTime
	if negotiatedTime == 0 {
		return &time.Ticker{}
	}
	sec := time.Second * time.Duration(fsm.pConf.Timers.State.KeepaliveInterval)
	if sec == 0 {
		sec = time.Second
	}
	return time.NewTicker(sec)
}

func (h *fsmHandler) sendMessageloop(ctx context.Context) *fsmStateReason {
	conn := h.conn
	fsm := h.fsm
	ticker := keepaliveTicker(fsm)
	send := func(m *bgp.BGPMessage) *fsmStateReason {
		fsm.lock.RLock()
		if fsm.twoByteAsTrans && m.Header.Type == bgp.BGP_MSG_UPDATE {
			fsm.logger.Debug("update for 2byte AS peer",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
					"Data":  m,
				})
			table.UpdatePathAttrs2ByteAs(m.Body.(*bgp.BGPUpdate))
			table.UpdatePathAggregator2ByteAs(m.Body.(*bgp.BGPUpdate))
		}

		// RFC8538 defines a Hard Reset notification subcode which
		// indicates that the BGP speaker wants to reset the session
		// without triggering graceful restart procedures. Here we map
		// notification subcodes to the Hard Reset subcode following
		// the RFC8538 suggestion.
		//
		// We check Status instead of Config because RFC8538 states
		// that A BGP speaker SHOULD NOT send a Hard Reset to a peer
		// from which it has not received the "N" bit.
		if fsm.pConf.GracefulRestart.State.NotificationEnabled && m.Header.Type == bgp.BGP_MSG_NOTIFICATION {
			if body := m.Body.(*bgp.BGPNotification); body.ErrorCode == bgp.BGP_ERROR_CEASE && bgp.ShouldHardReset(body.ErrorSubcode, false) {
				body.ErrorSubcode = bgp.BGP_ERROR_SUB_HARD_RESET
			}
		}

		b, err := m.Serialize(h.fsm.marshallingOptions)
		fsm.lock.RUnlock()
		if err != nil {
			fsm.lock.RLock()
			fsm.logger.Warn("failed to serialize",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
					"Data":  err,
				})
			fsm.lock.RUnlock()
			fsm.bgpMessageStateUpdate(0, false)
			return newfsmStateReason(fsmWriteFailed, nil, nil)
		}
		fsm.lock.RLock()
		err = conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(fsm.pConf.Timers.State.NegotiatedHoldTime)))
		fsm.lock.RUnlock()
		if err != nil {
			return newfsmStateReason(fsmWriteFailed, nil, nil)
		}
		_, err = conn.Write(b)
		if err != nil {
			fsm.lock.RLock()
			fsm.logger.Warn("failed to send",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
					"Data":  err,
				})
			fsm.lock.RUnlock()
			return newfsmStateReason(fsmWriteFailed, nil, nil)
		}
		fsm.bgpMessageStateUpdate(m.Header.Type, false)

		switch m.Header.Type {
		case bgp.BGP_MSG_NOTIFICATION:
			body := m.Body.(*bgp.BGPNotification)
			if body.ErrorCode == bgp.BGP_ERROR_CEASE && (body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN || body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET) {
				communication, rest := decodeAdministrativeCommunication(body.Data)
				fsm.lock.RLock()
				fsm.logger.Warn("sent notification",
					log.Fields{
						"Topic":               "Peer",
						"Key":                 fsm.pConf.State.NeighborAddress,
						"State":               fsm.state.String(),
						"Code":                body.ErrorCode,
						"Subcode":             body.ErrorSubcode,
						"Communicated-Reason": communication,
						"Data":                rest,
					})
				fsm.lock.RUnlock()
			} else {
				fsm.lock.RLock()
				fsm.logger.Warn("sent notification",
					log.Fields{
						"Topic":   "Peer",
						"Key":     fsm.pConf.State.NeighborAddress,
						"State":   fsm.state.String(),
						"Code":    body.ErrorCode,
						"Subcode": body.ErrorSubcode,
						"Data":    body.Data,
					})
				fsm.lock.RUnlock()
			}
			return newfsmStateReason(fsmNotificationSent, m, nil)
		case bgp.BGP_MSG_UPDATE:
			update := m.Body.(*bgp.BGPUpdate)
			if fsm.logger.GetLevel() >= log.DebugLevel {
				fsm.lock.RLock()
				fsm.logger.Debug("sent update",
					log.Fields{
						"Topic":       "Peer",
						"Key":         fsm.pConf.State.NeighborAddress,
						"State":       fsm.state.String(),
						"nlri":        update.NLRI,
						"withdrawals": update.WithdrawnRoutes,
						"attributes":  update.PathAttributes,
					})
				fsm.lock.RUnlock()
			}
		default:
			fsm.lock.RLock()
			fsm.logger.Debug("sent",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
					"data":  m,
				})
			fsm.lock.RUnlock()
		}
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case o := <-fsm.outgoingCh.Out():
			switch m := o.(type) {
			case *fsmOutgoingMsg:
				h.fsm.lock.RLock()
				options := h.fsm.marshallingOptions
				h.fsm.lock.RUnlock()
				for _, msg := range table.CreateUpdateMsgFromPaths(m.Paths, options) {
					if err := send(msg); err != nil {
						return err
					}
				}
				if m.Notification != nil {
					if m.StayIdle {
						// current user is only prefix-limit
						// fix me if this is not the case
						_ = fsm.changeadminState(adminStatePfxCt)
					}
					if err := send(m.Notification); err != nil {
						return err
					}
				}
			default:
				h.fsm.lock.RLock()
				fsm.logger.Warn("unexpected outgoing message",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.pConf.State.NeighborAddress,
						"State": fsm.state.String(),
					})
				h.fsm.lock.RUnlock()
			}
		case <-ticker.C:
			fmt.Println("Sending KeepAlive message")
			if err := send(bgp.NewBGPKeepAliveMessage()); err != nil {
				return err
			}
		}
	}
}

func (fsm *fsm) changeadminState(s adminState) error {
	fmt.Println("changeadminState called with state:", s.String())
	fsm.lock.Lock()
	defer fsm.lock.Unlock()

	if fsm.adminState != s {
		fsm.logger.Debug("admin state changed",
			log.Fields{
				"Topic":      "Peer",
				"Key":        fsm.pConf.State.NeighborAddress,
				"State":      fsm.state.String(),
				"adminState": s.String(),
			})
		fsm.adminState = s
		fsm.pConf.State.AdminDown = !fsm.pConf.State.AdminDown

		switch s {
		case adminStateUp:
			fsm.logger.Info("Administrative start",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
				})
		case adminStateDown:
			fsm.logger.Info("Administrative shutdown",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
				})
		case adminStatePfxCt:
			fsm.logger.Info("Administrative shutdown(Prefix limit reached)",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
				})
		}
	} else {
		fsm.logger.Warn("cannot change to the same state",
			log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.State.NeighborAddress,
				"State": fsm.state.String(),
			})
		return fmt.Errorf("cannot change to the same state")
	}
	return nil
}
