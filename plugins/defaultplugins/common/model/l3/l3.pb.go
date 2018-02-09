// Code generated by protoc-gen-gogo.
// source: l3.proto
// DO NOT EDIT!

/*
Package l3 is a generated protocol buffer package.

It is generated from these files:
	l3.proto

It has these top-level messages:
	StaticRoutes
	ArpTable
	ProxyArpRanges
	ProxyArpInterfaces
	STNTable
*/
package l3

import proto "github.com/gogo/protobuf/proto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal

// Static IPv4 / IPv6 routes
type StaticRoutes struct {
	Route []*StaticRoutes_Route `protobuf:"bytes,1,rep,name=route" json:"route,omitempty"`
}

func (m *StaticRoutes) Reset()         { *m = StaticRoutes{} }
func (m *StaticRoutes) String() string { return proto.CompactTextString(m) }
func (*StaticRoutes) ProtoMessage()    {}

func (m *StaticRoutes) GetRoute() []*StaticRoutes_Route {
	if m != nil {
		return m.Route
	}
	return nil
}

type StaticRoutes_Route struct {
	VrfId             uint32 `protobuf:"varint,1,opt,name=vrf_id,proto3" json:"vrf_id,omitempty"`
	Description       string `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
	DstIpAddr         string `protobuf:"bytes,3,opt,name=dst_ip_addr,proto3" json:"dst_ip_addr,omitempty"`
	NextHopAddr       string `protobuf:"bytes,4,opt,name=next_hop_addr,proto3" json:"next_hop_addr,omitempty"`
	OutgoingInterface string `protobuf:"bytes,5,opt,name=outgoing_interface,proto3" json:"outgoing_interface,omitempty"`
	Weight            uint32 `protobuf:"varint,6,opt,name=weight,proto3" json:"weight,omitempty"`
	Preference        uint32 `protobuf:"varint,7,opt,name=preference,proto3" json:"preference,omitempty"`
}

func (m *StaticRoutes_Route) Reset()         { *m = StaticRoutes_Route{} }
func (m *StaticRoutes_Route) String() string { return proto.CompactTextString(m) }
func (*StaticRoutes_Route) ProtoMessage()    {}

// Static IP ARP entries
type ArpTable struct {
	ArpTableEntries []*ArpTable_ArpTableEntry `protobuf:"bytes,100,rep,name=arp_table_entries" json:"arp_table_entries,omitempty"`
}

func (m *ArpTable) Reset()         { *m = ArpTable{} }
func (m *ArpTable) String() string { return proto.CompactTextString(m) }
func (*ArpTable) ProtoMessage()    {}

func (m *ArpTable) GetArpTableEntries() []*ArpTable_ArpTableEntry {
	if m != nil {
		return m.ArpTableEntries
	}
	return nil
}

type ArpTable_ArpTableEntry struct {
	Interface   string `protobuf:"bytes,1,opt,name=interface,proto3" json:"interface,omitempty"`
	IpAddress   string `protobuf:"bytes,2,opt,name=ip_address,proto3" json:"ip_address,omitempty"`
	PhysAddress string `protobuf:"bytes,3,opt,name=phys_address,proto3" json:"phys_address,omitempty"`
	Static      bool   `protobuf:"varint,4,opt,name=static,proto3" json:"static,omitempty"`
}

func (m *ArpTable_ArpTableEntry) Reset()         { *m = ArpTable_ArpTableEntry{} }
func (m *ArpTable_ArpTableEntry) String() string { return proto.CompactTextString(m) }
func (*ArpTable_ArpTableEntry) ProtoMessage()    {}

// Proxy ARP ranges
type ProxyArpRanges struct {
	ProxyArpRanges []*ProxyArpRanges_ProxyArpRange `protobuf:"bytes,100,rep,name=proxy_arp_ranges" json:"proxy_arp_ranges,omitempty"`
}

func (m *ProxyArpRanges) Reset()         { *m = ProxyArpRanges{} }
func (m *ProxyArpRanges) String() string { return proto.CompactTextString(m) }
func (*ProxyArpRanges) ProtoMessage()    {}

func (m *ProxyArpRanges) GetProxyArpRanges() []*ProxyArpRanges_ProxyArpRange {
	if m != nil {
		return m.ProxyArpRanges
	}
	return nil
}

type ProxyArpRanges_ProxyArpRange struct {
	RangeIpStart string `protobuf:"bytes,1,opt,name=range_ip_start,proto3" json:"range_ip_start,omitempty"`
	RangeIpEnd   string `protobuf:"bytes,2,opt,name=range_ip_end,proto3" json:"range_ip_end,omitempty"`
}

func (m *ProxyArpRanges_ProxyArpRange) Reset()         { *m = ProxyArpRanges_ProxyArpRange{} }
func (m *ProxyArpRanges_ProxyArpRange) String() string { return proto.CompactTextString(m) }
func (*ProxyArpRanges_ProxyArpRange) ProtoMessage()    {}

// Proxy ARP interfaces
type ProxyArpInterfaces struct {
	ProxyArpInterfaces []*ProxyArpInterfaces_ProxyArpInterface `protobuf:"bytes,100,rep,name=proxy_arp_interfaces" json:"proxy_arp_interfaces,omitempty"`
}

func (m *ProxyArpInterfaces) Reset()         { *m = ProxyArpInterfaces{} }
func (m *ProxyArpInterfaces) String() string { return proto.CompactTextString(m) }
func (*ProxyArpInterfaces) ProtoMessage()    {}

func (m *ProxyArpInterfaces) GetProxyArpInterfaces() []*ProxyArpInterfaces_ProxyArpInterface {
	if m != nil {
		return m.ProxyArpInterfaces
	}
	return nil
}

type ProxyArpInterfaces_ProxyArpInterface struct {
	Interface string `protobuf:"bytes,1,opt,name=interface,proto3" json:"interface,omitempty"`
}

func (m *ProxyArpInterfaces_ProxyArpInterface) Reset()         { *m = ProxyArpInterfaces_ProxyArpInterface{} }
func (m *ProxyArpInterfaces_ProxyArpInterface) String() string { return proto.CompactTextString(m) }
func (*ProxyArpInterfaces_ProxyArpInterface) ProtoMessage()    {}

// STN (Steal The NIC) feature table
type STNTable struct {
	StnTableEntries []*STNTable_STNTableEntry `protobuf:"bytes,100,rep,name=stn_table_entries" json:"stn_table_entries,omitempty"`
}

func (m *STNTable) Reset()         { *m = STNTable{} }
func (m *STNTable) String() string { return proto.CompactTextString(m) }
func (*STNTable) ProtoMessage()    {}

func (m *STNTable) GetStnTableEntries() []*STNTable_STNTableEntry {
	if m != nil {
		return m.StnTableEntries
	}
	return nil
}

type STNTable_STNTableEntry struct {
	IpAddress string `protobuf:"bytes,1,opt,name=ip_address,proto3" json:"ip_address,omitempty"`
	Interface string `protobuf:"bytes,2,opt,name=interface,proto3" json:"interface,omitempty"`
}

func (m *STNTable_STNTableEntry) Reset()         { *m = STNTable_STNTableEntry{} }
func (m *STNTable_STNTableEntry) String() string { return proto.CompactTextString(m) }
func (*STNTable_STNTableEntry) ProtoMessage()    {}