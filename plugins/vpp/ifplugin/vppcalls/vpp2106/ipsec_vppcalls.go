//  Copyright (c) 2019 Cisco and/or its affiliates.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package vpp2106

import (
	"context"
	"encoding/hex"

	vpp_ipsec "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2106/ipsec"
	ifs "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
)

// AddIPSecTunnelInterface adds a new IPSec tunnel interface.
func (h *InterfaceVppHandler) AddIPSecTunnelInterface(ctx context.Context, ifName string, ipSecLink *ifs.IPSecLink) (uint32, error) {
	return h.tunnelIfAddDel(ctx, ifName, ipSecLink, true)
}

// DeleteIPSecTunnelInterface removes existing IPSec tunnel interface.
func (h *InterfaceVppHandler) DeleteIPSecTunnelInterface(ctx context.Context, ifName string, ipSecLink *ifs.IPSecLink) error {
	// Note: ifIdx is not used now, tunnel should be matched based on parameters
	_, err := h.tunnelIfAddDel(ctx, ifName, ipSecLink, false)
	return err
}

// modified to use IpsecSadEntryAddDel instead of IpsecTunnelIfAddDel
// comment tags:
// -: present in tunnel, not present in sad (LocalXXX and RemoteXXX merged into XXX)
// +: not present in tunnel, present in sad
func (h *InterfaceVppHandler) tunnelIfAddDel(ctx context.Context, ipSecLink *ifs.IPSecLink, isAdd bool) (uint32, error) {
	// ctx not used any more

	cryptoKey, err := hex.DecodeString(ipSecLink.LocalCryptoKey)
	// - cryptoKey, err := hex.DecodeString(ipSecLink.RemoteCryptoKey)
	if err != nil {
		return err
	}
	integKey, err := hex.DecodeString(ipSecLink.LocalIntegKey)
	// - integKey, err := hex.DecodeString(ipSecLink.RemoteIntegKey)
	if err != nil {
		return err
	}

	var flags ipsec_types.IpsecSadFlags
	if ipSecLink.Esn {
		flags |= ipsec_types.IPSEC_API_SAD_FLAG_USE_ESN
	}
	if ipSecLink.AntiReplay {
		flags |= ipsec_types.IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY
	}
	if ipSecLink.EnableUdpEncap {
		flags |= ipsec_types.IPSEC_API_SAD_FLAG_UDP_ENCAP
	}
	var tunnelSrc, tunnelDst ip_types.Address
	if ipSecLink.LocalIp != "" {
		flags |= ipsec_types.IPSEC_API_SAD_FLAG_IS_TUNNEL
		isIPv6, err := addrs.IsIPv6(ipSecLink.LocalIp)
		if err != nil {
			return err
		}
		if isIPv6 {
			flags |= ipsec_types.IPSEC_API_SAD_FLAG_IS_TUNNEL_V6
		}
		tunnelSrc, err = IPToAddress(ipSecLink.LocalIp)
		if err != nil {
			return err
		}
		tunnelDst, err = IPToAddress(ipSecLink.RemoteIp)
		if err != nil {
			return err
		}
	}
	const undefinedPort = ^uint16(0)
	udpSrcPort := undefinedPort
	// + if sa.TunnelSrcPort != 0 {
	// + udpSrcPort = uint16(sa.TunnelSrcPort)
	// + }
	udpDstPort := undefinedPort
	// + if sa.TunnelDstPort != 0 {
	// + udpDstPort = uint16(sa.TunnelDstPort)
	// + }

	req := &vpp_ipsec.IpsecSadEntryAddDel{
		IsAdd: isAdd,
		Entry: ipsec_types.IpsecSadEntry{
			// + SadID:    sa.Index,
			Spi: ipSecLink.LocalSpi,
			// - Spi: ipSecLink.RemoteSpi,
			// + Protocol: protocolToIpsecProto(sa.Protocol),
			CryptoAlgorithm: ipsec_types.IpsecCryptoAlg(ipSecLink.CryptoAlg),
			CryptoKey: ipsec_types.Key{
				Data:   cryptoKey,
				Length: uint8(len(cryptoKey)),
			},
			// + Salt:     sa.CryptoSalt,
			IntegrityAlgorithm: ipsec_types.IpsecIntegAlg(ipSecLink.IntegAlg),
			IntegrityKey: ipsec_types.Key{
				Data:   integKey,
				Length: uint8(len(integKey)),
			},
			TunnelSrc:  tunnelSrc,
			TunnelDst:  tunnelDst,
			Flags:      flags,
			UDPSrcPort: udpSrcPort,
			UDPDstPort: udpDstPort,
		},
	}
	reply := &vpp_ipsec.IpsecSadEntryAddDelReply{}

	if err = h.callsChannel.SendRequest(req).ReceiveReply(reply); err != nil {
		return err
	}

	return uint32(reply.SwIfIndex), nil
}
