// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.4
// source: ligato/linux/l3/route.proto

package linux_l3

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

type Route_Scope int32

const (
	Route_UNDEFINED Route_Scope = 0
	Route_GLOBAL    Route_Scope = 1
	Route_SITE      Route_Scope = 2
	Route_LINK      Route_Scope = 3
	Route_HOST      Route_Scope = 4
)

// Enum value maps for Route_Scope.
var (
	Route_Scope_name = map[int32]string{
		0: "UNDEFINED",
		1: "GLOBAL",
		2: "SITE",
		3: "LINK",
		4: "HOST",
	}
	Route_Scope_value = map[string]int32{
		"UNDEFINED": 0,
		"GLOBAL":    1,
		"SITE":      2,
		"LINK":      3,
		"HOST":      4,
	}
)

func (x Route_Scope) Enum() *Route_Scope {
	p := new(Route_Scope)
	*p = x
	return p
}

func (x Route_Scope) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Route_Scope) Descriptor() protoreflect.EnumDescriptor {
	return file_ligato_linux_l3_route_proto_enumTypes[0].Descriptor()
}

func (Route_Scope) Type() protoreflect.EnumType {
	return &file_ligato_linux_l3_route_proto_enumTypes[0]
}

func (x Route_Scope) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Route_Scope.Descriptor instead.
func (Route_Scope) EnumDescriptor() ([]byte, []int) {
	return file_ligato_linux_l3_route_proto_rawDescGZIP(), []int{0, 0}
}

type Route struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Outgoing interface logical name (mandatory).
	OutgoingInterface string `protobuf:"bytes,1,opt,name=outgoing_interface,json=outgoingInterface,proto3" json:"outgoing_interface,omitempty"`
	// The scope of the area where the link is valid.
	Scope Route_Scope `protobuf:"varint,2,opt,name=scope,proto3,enum=ligato.linux.l3.Route_Scope" json:"scope,omitempty"`
	// Destination network address in the format <address>/<prefix> (mandatory)
	// Address can be also allocated via netalloc plugin and referenced here,
	// see: api/models/netalloc/netalloc.proto
	DstNetwork string `protobuf:"bytes,3,opt,name=dst_network,json=dstNetwork,proto3" json:"dst_network,omitempty"`
	// Gateway IP address (without mask, optional).
	// Address can be also allocated via netalloc plugin and referenced here,
	// see: api/models/netalloc/netalloc.proto
	GwAddr string `protobuf:"bytes,4,opt,name=gw_addr,json=gwAddr,proto3" json:"gw_addr,omitempty"`
	// routing metric (weight)
	Metric uint32 `protobuf:"varint,5,opt,name=metric,proto3" json:"metric,omitempty"`
}

func (x *Route) Reset() {
	*x = Route{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ligato_linux_l3_route_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Route) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Route) ProtoMessage() {}

func (x *Route) ProtoReflect() protoreflect.Message {
	mi := &file_ligato_linux_l3_route_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Route.ProtoReflect.Descriptor instead.
func (*Route) Descriptor() ([]byte, []int) {
	return file_ligato_linux_l3_route_proto_rawDescGZIP(), []int{0}
}

func (x *Route) GetOutgoingInterface() string {
	if x != nil {
		return x.OutgoingInterface
	}
	return ""
}

func (x *Route) GetScope() Route_Scope {
	if x != nil {
		return x.Scope
	}
	return Route_UNDEFINED
}

func (x *Route) GetDstNetwork() string {
	if x != nil {
		return x.DstNetwork
	}
	return ""
}

func (x *Route) GetGwAddr() string {
	if x != nil {
		return x.GwAddr
	}
	return ""
}

func (x *Route) GetMetric() uint32 {
	if x != nil {
		return x.Metric
	}
	return 0
}

var File_ligato_linux_l3_route_proto protoreflect.FileDescriptor

var file_ligato_linux_l3_route_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x6c, 0x69, 0x67, 0x61, 0x74, 0x6f, 0x2f, 0x6c, 0x69, 0x6e, 0x75, 0x78, 0x2f, 0x6c,
	0x33, 0x2f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0f, 0x6c,
	0x69, 0x67, 0x61, 0x74, 0x6f, 0x2e, 0x6c, 0x69, 0x6e, 0x75, 0x78, 0x2e, 0x6c, 0x33, 0x1a, 0x18,
	0x6c, 0x69, 0x67, 0x61, 0x74, 0x6f, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x8c, 0x02, 0x0a, 0x05, 0x52, 0x6f, 0x75,
	0x74, 0x65, 0x12, 0x2d, 0x0a, 0x12, 0x6f, 0x75, 0x74, 0x67, 0x6f, 0x69, 0x6e, 0x67, 0x5f, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11,
	0x6f, 0x75, 0x74, 0x67, 0x6f, 0x69, 0x6e, 0x67, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63,
	0x65, 0x12, 0x32, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x1c, 0x2e, 0x6c, 0x69, 0x67, 0x61, 0x74, 0x6f, 0x2e, 0x6c, 0x69, 0x6e, 0x75, 0x78, 0x2e,
	0x6c, 0x33, 0x2e, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x2e, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x05,
	0x73, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x26, 0x0a, 0x0b, 0x64, 0x73, 0x74, 0x5f, 0x6e, 0x65, 0x74,
	0x77, 0x6f, 0x72, 0x6b, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x42, 0x05, 0x82, 0x7d, 0x02, 0x08,
	0x04, 0x52, 0x0a, 0x64, 0x73, 0x74, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x12, 0x1e, 0x0a,
	0x07, 0x67, 0x77, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x42, 0x05,
	0x82, 0x7d, 0x02, 0x08, 0x01, 0x52, 0x06, 0x67, 0x77, 0x41, 0x64, 0x64, 0x72, 0x12, 0x16, 0x0a,
	0x06, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x6d,
	0x65, 0x74, 0x72, 0x69, 0x63, 0x22, 0x40, 0x0a, 0x05, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x0d,
	0x0a, 0x09, 0x55, 0x4e, 0x44, 0x45, 0x46, 0x49, 0x4e, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0a, 0x0a,
	0x06, 0x47, 0x4c, 0x4f, 0x42, 0x41, 0x4c, 0x10, 0x01, 0x12, 0x08, 0x0a, 0x04, 0x53, 0x49, 0x54,
	0x45, 0x10, 0x02, 0x12, 0x08, 0x0a, 0x04, 0x4c, 0x49, 0x4e, 0x4b, 0x10, 0x03, 0x12, 0x08, 0x0a,
	0x04, 0x48, 0x4f, 0x53, 0x54, 0x10, 0x04, 0x42, 0x3a, 0x5a, 0x38, 0x67, 0x6f, 0x2e, 0x6c, 0x69,
	0x67, 0x61, 0x74, 0x6f, 0x2e, 0x69, 0x6f, 0x2f, 0x76, 0x70, 0x70, 0x2d, 0x61, 0x67, 0x65, 0x6e,
	0x74, 0x2f, 0x76, 0x33, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x6c, 0x69, 0x67, 0x61, 0x74,
	0x6f, 0x2f, 0x6c, 0x69, 0x6e, 0x75, 0x78, 0x2f, 0x6c, 0x33, 0x3b, 0x6c, 0x69, 0x6e, 0x75, 0x78,
	0x5f, 0x6c, 0x33, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ligato_linux_l3_route_proto_rawDescOnce sync.Once
	file_ligato_linux_l3_route_proto_rawDescData = file_ligato_linux_l3_route_proto_rawDesc
)

func file_ligato_linux_l3_route_proto_rawDescGZIP() []byte {
	file_ligato_linux_l3_route_proto_rawDescOnce.Do(func() {
		file_ligato_linux_l3_route_proto_rawDescData = protoimpl.X.CompressGZIP(file_ligato_linux_l3_route_proto_rawDescData)
	})
	return file_ligato_linux_l3_route_proto_rawDescData
}

var file_ligato_linux_l3_route_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_ligato_linux_l3_route_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ligato_linux_l3_route_proto_goTypes = []interface{}{
	(Route_Scope)(0), // 0: ligato.linux.l3.Route.Scope
	(*Route)(nil),    // 1: ligato.linux.l3.Route
}
var file_ligato_linux_l3_route_proto_depIdxs = []int32{
	0, // 0: ligato.linux.l3.Route.scope:type_name -> ligato.linux.l3.Route.Scope
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_ligato_linux_l3_route_proto_init() }
func file_ligato_linux_l3_route_proto_init() {
	if File_ligato_linux_l3_route_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ligato_linux_l3_route_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Route); i {
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
			RawDescriptor: file_ligato_linux_l3_route_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ligato_linux_l3_route_proto_goTypes,
		DependencyIndexes: file_ligato_linux_l3_route_proto_depIdxs,
		EnumInfos:         file_ligato_linux_l3_route_proto_enumTypes,
		MessageInfos:      file_ligato_linux_l3_route_proto_msgTypes,
	}.Build()
	File_ligato_linux_l3_route_proto = out.File
	file_ligato_linux_l3_route_proto_rawDesc = nil
	file_ligato_linux_l3_route_proto_goTypes = nil
	file_ligato_linux_l3_route_proto_depIdxs = nil
}
