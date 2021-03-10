// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.4
// source: ligato/vpp/l3/teib.proto

package vpp_l3

import (
	proto "github.com/golang/protobuf/proto"
	_ "go.ligato.io/vpp-agent/v3/proto/ligato"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

// TeibEntry represents an tunnel endpoint information base entry.
type TeibEntry struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Interface references a tunnel interface this TEIB entry is linked to.
	Interface string `protobuf:"bytes,1,opt,name=interface,proto3" json:"interface,omitempty"`
	// IP address of the peer.
	PeerAddr string `protobuf:"bytes,2,opt,name=peer_addr,json=peerAddr,proto3" json:"peer_addr,omitempty"`
	// Next hop IP address.
	NextHopAddr string `protobuf:"bytes,3,opt,name=next_hop_addr,json=nextHopAddr,proto3" json:"next_hop_addr,omitempty"`
	// VRF ID used to reach the next hop.
	VrfId uint32 `protobuf:"varint,4,opt,name=vrf_id,json=vrfId,proto3" json:"vrf_id,omitempty"`
}

func (x *TeibEntry) Reset() {
	*x = TeibEntry{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ligato_vpp_l3_teib_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TeibEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TeibEntry) ProtoMessage() {}

func (x *TeibEntry) ProtoReflect() protoreflect.Message {
	mi := &file_ligato_vpp_l3_teib_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TeibEntry.ProtoReflect.Descriptor instead.
func (*TeibEntry) Descriptor() ([]byte, []int) {
	return file_ligato_vpp_l3_teib_proto_rawDescGZIP(), []int{0}
}

func (x *TeibEntry) GetInterface() string {
	if x != nil {
		return x.Interface
	}
	return ""
}

func (x *TeibEntry) GetPeerAddr() string {
	if x != nil {
		return x.PeerAddr
	}
	return ""
}

func (x *TeibEntry) GetNextHopAddr() string {
	if x != nil {
		return x.NextHopAddr
	}
	return ""
}

func (x *TeibEntry) GetVrfId() uint32 {
	if x != nil {
		return x.VrfId
	}
	return 0
}

var File_ligato_vpp_l3_teib_proto protoreflect.FileDescriptor

var file_ligato_vpp_l3_teib_proto_rawDesc = []byte{
	0x0a, 0x18, 0x6c, 0x69, 0x67, 0x61, 0x74, 0x6f, 0x2f, 0x76, 0x70, 0x70, 0x2f, 0x6c, 0x33, 0x2f,
	0x74, 0x65, 0x69, 0x62, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x6c, 0x69, 0x67, 0x61,
	0x74, 0x6f, 0x2e, 0x76, 0x70, 0x70, 0x2e, 0x6c, 0x33, 0x1a, 0x18, 0x6c, 0x69, 0x67, 0x61, 0x74,
	0x6f, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x8f, 0x01, 0x0a, 0x09, 0x54, 0x65, 0x69, 0x62, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x12, 0x1c, 0x0a, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x12,
	0x22, 0x0a, 0x09, 0x70, 0x65, 0x65, 0x72, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x42, 0x05, 0x82, 0x7d, 0x02, 0x08, 0x01, 0x52, 0x08, 0x70, 0x65, 0x65, 0x72, 0x41,
	0x64, 0x64, 0x72, 0x12, 0x29, 0x0a, 0x0d, 0x6e, 0x65, 0x78, 0x74, 0x5f, 0x68, 0x6f, 0x70, 0x5f,
	0x61, 0x64, 0x64, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x05, 0x82, 0x7d, 0x02, 0x08,
	0x01, 0x52, 0x0b, 0x6e, 0x65, 0x78, 0x74, 0x48, 0x6f, 0x70, 0x41, 0x64, 0x64, 0x72, 0x12, 0x15,
	0x0a, 0x06, 0x76, 0x72, 0x66, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05,
	0x76, 0x72, 0x66, 0x49, 0x64, 0x42, 0x36, 0x5a, 0x34, 0x67, 0x6f, 0x2e, 0x6c, 0x69, 0x67, 0x61,
	0x74, 0x6f, 0x2e, 0x69, 0x6f, 0x2f, 0x76, 0x70, 0x70, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2f,
	0x76, 0x33, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x6c, 0x69, 0x67, 0x61, 0x74, 0x6f, 0x2f,
	0x76, 0x70, 0x70, 0x2f, 0x6c, 0x33, 0x3b, 0x76, 0x70, 0x70, 0x5f, 0x6c, 0x33, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ligato_vpp_l3_teib_proto_rawDescOnce sync.Once
	file_ligato_vpp_l3_teib_proto_rawDescData = file_ligato_vpp_l3_teib_proto_rawDesc
)

func file_ligato_vpp_l3_teib_proto_rawDescGZIP() []byte {
	file_ligato_vpp_l3_teib_proto_rawDescOnce.Do(func() {
		file_ligato_vpp_l3_teib_proto_rawDescData = protoimpl.X.CompressGZIP(file_ligato_vpp_l3_teib_proto_rawDescData)
	})
	return file_ligato_vpp_l3_teib_proto_rawDescData
}

var file_ligato_vpp_l3_teib_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ligato_vpp_l3_teib_proto_goTypes = []interface{}{
	(*TeibEntry)(nil), // 0: ligato.vpp.l3.TeibEntry
}
var file_ligato_vpp_l3_teib_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_ligato_vpp_l3_teib_proto_init() }
func file_ligato_vpp_l3_teib_proto_init() {
	if File_ligato_vpp_l3_teib_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ligato_vpp_l3_teib_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TeibEntry); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_ligato_vpp_l3_teib_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ligato_vpp_l3_teib_proto_goTypes,
		DependencyIndexes: file_ligato_vpp_l3_teib_proto_depIdxs,
		MessageInfos:      file_ligato_vpp_l3_teib_proto_msgTypes,
	}.Build()
	File_ligato_vpp_l3_teib_proto = out.File
	file_ligato_vpp_l3_teib_proto_rawDesc = nil
	file_ligato_vpp_l3_teib_proto_goTypes = nil
	file_ligato_vpp_l3_teib_proto_depIdxs = nil
}
