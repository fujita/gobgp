// Copyright (C) 2018-2021 Nippon Telegraph and Telephone Corporation.
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation files
// (the "Software"), to deal in the Software without restriction,
// including without limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of the Software,
// and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.22.0
// 	protoc        v3.14.0
// source: capability.proto

package apipb

import (
	proto "github.com/golang/protobuf/proto"
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

type AddPathMode int32

const (
	AddPathMode_MODE_NONE    AddPathMode = 0
	AddPathMode_MODE_RECEIVE AddPathMode = 1
	AddPathMode_MODE_SEND    AddPathMode = 2
	AddPathMode_MODE_BOTH    AddPathMode = 3
)

// Enum value maps for AddPathMode.
var (
	AddPathMode_name = map[int32]string{
		0: "MODE_NONE",
		1: "MODE_RECEIVE",
		2: "MODE_SEND",
		3: "MODE_BOTH",
	}
	AddPathMode_value = map[string]int32{
		"MODE_NONE":    0,
		"MODE_RECEIVE": 1,
		"MODE_SEND":    2,
		"MODE_BOTH":    3,
	}
)

func (x AddPathMode) Enum() *AddPathMode {
	p := new(AddPathMode)
	*p = x
	return p
}

func (x AddPathMode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AddPathMode) Descriptor() protoreflect.EnumDescriptor {
	return file_capability_proto_enumTypes[0].Descriptor()
}

func (AddPathMode) Type() protoreflect.EnumType {
	return &file_capability_proto_enumTypes[0]
}

func (x AddPathMode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AddPathMode.Descriptor instead.
func (AddPathMode) EnumDescriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{0}
}

type MultiProtocolCapability struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Family *Family `protobuf:"bytes,1,opt,name=family,proto3" json:"family,omitempty"`
}

func (x *MultiProtocolCapability) Reset() {
	*x = MultiProtocolCapability{}
	if protoimpl.UnsafeEnabled {
		mi := &file_capability_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MultiProtocolCapability) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MultiProtocolCapability) ProtoMessage() {}

func (x *MultiProtocolCapability) ProtoReflect() protoreflect.Message {
	mi := &file_capability_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MultiProtocolCapability.ProtoReflect.Descriptor instead.
func (*MultiProtocolCapability) Descriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{0}
}

func (x *MultiProtocolCapability) GetFamily() *Family {
	if x != nil {
		return x.Family
	}
	return nil
}

type RouteRefreshCapability struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RouteRefreshCapability) Reset() {
	*x = RouteRefreshCapability{}
	if protoimpl.UnsafeEnabled {
		mi := &file_capability_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RouteRefreshCapability) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RouteRefreshCapability) ProtoMessage() {}

func (x *RouteRefreshCapability) ProtoReflect() protoreflect.Message {
	mi := &file_capability_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RouteRefreshCapability.ProtoReflect.Descriptor instead.
func (*RouteRefreshCapability) Descriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{1}
}

type CarryingLabelInfoCapability struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *CarryingLabelInfoCapability) Reset() {
	*x = CarryingLabelInfoCapability{}
	if protoimpl.UnsafeEnabled {
		mi := &file_capability_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CarryingLabelInfoCapability) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CarryingLabelInfoCapability) ProtoMessage() {}

func (x *CarryingLabelInfoCapability) ProtoReflect() protoreflect.Message {
	mi := &file_capability_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CarryingLabelInfoCapability.ProtoReflect.Descriptor instead.
func (*CarryingLabelInfoCapability) Descriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{2}
}

type ExtendedNexthopCapabilityTuple struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	NlriFamily *Family `protobuf:"bytes,1,opt,name=nlri_family,json=nlriFamily,proto3" json:"nlri_family,omitempty"`
	// Nexthop AFI must be either
	// gobgp.IPv4 or
	// gobgp.IPv6.
	NexthopFamily *Family `protobuf:"bytes,2,opt,name=nexthop_family,json=nexthopFamily,proto3" json:"nexthop_family,omitempty"`
}

func (x *ExtendedNexthopCapabilityTuple) Reset() {
	*x = ExtendedNexthopCapabilityTuple{}
	if protoimpl.UnsafeEnabled {
		mi := &file_capability_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExtendedNexthopCapabilityTuple) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExtendedNexthopCapabilityTuple) ProtoMessage() {}

func (x *ExtendedNexthopCapabilityTuple) ProtoReflect() protoreflect.Message {
	mi := &file_capability_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExtendedNexthopCapabilityTuple.ProtoReflect.Descriptor instead.
func (*ExtendedNexthopCapabilityTuple) Descriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{3}
}

func (x *ExtendedNexthopCapabilityTuple) GetNlriFamily() *Family {
	if x != nil {
		return x.NlriFamily
	}
	return nil
}

func (x *ExtendedNexthopCapabilityTuple) GetNexthopFamily() *Family {
	if x != nil {
		return x.NexthopFamily
	}
	return nil
}

type ExtendedNexthopCapability struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Tuples []*ExtendedNexthopCapabilityTuple `protobuf:"bytes,1,rep,name=tuples,proto3" json:"tuples,omitempty"`
}

func (x *ExtendedNexthopCapability) Reset() {
	*x = ExtendedNexthopCapability{}
	if protoimpl.UnsafeEnabled {
		mi := &file_capability_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExtendedNexthopCapability) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExtendedNexthopCapability) ProtoMessage() {}

func (x *ExtendedNexthopCapability) ProtoReflect() protoreflect.Message {
	mi := &file_capability_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExtendedNexthopCapability.ProtoReflect.Descriptor instead.
func (*ExtendedNexthopCapability) Descriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{4}
}

func (x *ExtendedNexthopCapability) GetTuples() []*ExtendedNexthopCapabilityTuple {
	if x != nil {
		return x.Tuples
	}
	return nil
}

type GracefulRestartCapabilityTuple struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Family *Family `protobuf:"bytes,1,opt,name=family,proto3" json:"family,omitempty"`
	Flags  uint32  `protobuf:"varint,2,opt,name=flags,proto3" json:"flags,omitempty"`
}

func (x *GracefulRestartCapabilityTuple) Reset() {
	*x = GracefulRestartCapabilityTuple{}
	if protoimpl.UnsafeEnabled {
		mi := &file_capability_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GracefulRestartCapabilityTuple) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GracefulRestartCapabilityTuple) ProtoMessage() {}

func (x *GracefulRestartCapabilityTuple) ProtoReflect() protoreflect.Message {
	mi := &file_capability_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GracefulRestartCapabilityTuple.ProtoReflect.Descriptor instead.
func (*GracefulRestartCapabilityTuple) Descriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{5}
}

func (x *GracefulRestartCapabilityTuple) GetFamily() *Family {
	if x != nil {
		return x.Family
	}
	return nil
}

func (x *GracefulRestartCapabilityTuple) GetFlags() uint32 {
	if x != nil {
		return x.Flags
	}
	return 0
}

type GracefulRestartCapability struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Flags  uint32                            `protobuf:"varint,1,opt,name=flags,proto3" json:"flags,omitempty"`
	Time   uint32                            `protobuf:"varint,2,opt,name=time,proto3" json:"time,omitempty"`
	Tuples []*GracefulRestartCapabilityTuple `protobuf:"bytes,3,rep,name=tuples,proto3" json:"tuples,omitempty"`
}

func (x *GracefulRestartCapability) Reset() {
	*x = GracefulRestartCapability{}
	if protoimpl.UnsafeEnabled {
		mi := &file_capability_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GracefulRestartCapability) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GracefulRestartCapability) ProtoMessage() {}

func (x *GracefulRestartCapability) ProtoReflect() protoreflect.Message {
	mi := &file_capability_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GracefulRestartCapability.ProtoReflect.Descriptor instead.
func (*GracefulRestartCapability) Descriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{6}
}

func (x *GracefulRestartCapability) GetFlags() uint32 {
	if x != nil {
		return x.Flags
	}
	return 0
}

func (x *GracefulRestartCapability) GetTime() uint32 {
	if x != nil {
		return x.Time
	}
	return 0
}

func (x *GracefulRestartCapability) GetTuples() []*GracefulRestartCapabilityTuple {
	if x != nil {
		return x.Tuples
	}
	return nil
}

type FourOctetASNumberCapability struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	As uint32 `protobuf:"varint,1,opt,name=as,proto3" json:"as,omitempty"`
}

func (x *FourOctetASNumberCapability) Reset() {
	*x = FourOctetASNumberCapability{}
	if protoimpl.UnsafeEnabled {
		mi := &file_capability_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FourOctetASNumberCapability) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FourOctetASNumberCapability) ProtoMessage() {}

func (x *FourOctetASNumberCapability) ProtoReflect() protoreflect.Message {
	mi := &file_capability_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FourOctetASNumberCapability.ProtoReflect.Descriptor instead.
func (*FourOctetASNumberCapability) Descriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{7}
}

func (x *FourOctetASNumberCapability) GetAs() uint32 {
	if x != nil {
		return x.As
	}
	return 0
}

type AddPathCapabilityTuple struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Family *Family     `protobuf:"bytes,1,opt,name=family,proto3" json:"family,omitempty"`
	Mode   AddPathMode `protobuf:"varint,2,opt,name=mode,proto3,enum=apipb.AddPathMode" json:"mode,omitempty"`
}

func (x *AddPathCapabilityTuple) Reset() {
	*x = AddPathCapabilityTuple{}
	if protoimpl.UnsafeEnabled {
		mi := &file_capability_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AddPathCapabilityTuple) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddPathCapabilityTuple) ProtoMessage() {}

func (x *AddPathCapabilityTuple) ProtoReflect() protoreflect.Message {
	mi := &file_capability_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddPathCapabilityTuple.ProtoReflect.Descriptor instead.
func (*AddPathCapabilityTuple) Descriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{8}
}

func (x *AddPathCapabilityTuple) GetFamily() *Family {
	if x != nil {
		return x.Family
	}
	return nil
}

func (x *AddPathCapabilityTuple) GetMode() AddPathMode {
	if x != nil {
		return x.Mode
	}
	return AddPathMode_MODE_NONE
}

type AddPathCapability struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Tuples []*AddPathCapabilityTuple `protobuf:"bytes,1,rep,name=tuples,proto3" json:"tuples,omitempty"`
}

func (x *AddPathCapability) Reset() {
	*x = AddPathCapability{}
	if protoimpl.UnsafeEnabled {
		mi := &file_capability_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AddPathCapability) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddPathCapability) ProtoMessage() {}

func (x *AddPathCapability) ProtoReflect() protoreflect.Message {
	mi := &file_capability_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddPathCapability.ProtoReflect.Descriptor instead.
func (*AddPathCapability) Descriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{9}
}

func (x *AddPathCapability) GetTuples() []*AddPathCapabilityTuple {
	if x != nil {
		return x.Tuples
	}
	return nil
}

type EnhancedRouteRefreshCapability struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *EnhancedRouteRefreshCapability) Reset() {
	*x = EnhancedRouteRefreshCapability{}
	if protoimpl.UnsafeEnabled {
		mi := &file_capability_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnhancedRouteRefreshCapability) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnhancedRouteRefreshCapability) ProtoMessage() {}

func (x *EnhancedRouteRefreshCapability) ProtoReflect() protoreflect.Message {
	mi := &file_capability_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnhancedRouteRefreshCapability.ProtoReflect.Descriptor instead.
func (*EnhancedRouteRefreshCapability) Descriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{10}
}

type LongLivedGracefulRestartCapabilityTuple struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Family *Family `protobuf:"bytes,1,opt,name=family,proto3" json:"family,omitempty"`
	Flags  uint32  `protobuf:"varint,2,opt,name=flags,proto3" json:"flags,omitempty"`
	Time   uint32  `protobuf:"varint,3,opt,name=time,proto3" json:"time,omitempty"`
}

func (x *LongLivedGracefulRestartCapabilityTuple) Reset() {
	*x = LongLivedGracefulRestartCapabilityTuple{}
	if protoimpl.UnsafeEnabled {
		mi := &file_capability_proto_msgTypes[11]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LongLivedGracefulRestartCapabilityTuple) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LongLivedGracefulRestartCapabilityTuple) ProtoMessage() {}

func (x *LongLivedGracefulRestartCapabilityTuple) ProtoReflect() protoreflect.Message {
	mi := &file_capability_proto_msgTypes[11]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LongLivedGracefulRestartCapabilityTuple.ProtoReflect.Descriptor instead.
func (*LongLivedGracefulRestartCapabilityTuple) Descriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{11}
}

func (x *LongLivedGracefulRestartCapabilityTuple) GetFamily() *Family {
	if x != nil {
		return x.Family
	}
	return nil
}

func (x *LongLivedGracefulRestartCapabilityTuple) GetFlags() uint32 {
	if x != nil {
		return x.Flags
	}
	return 0
}

func (x *LongLivedGracefulRestartCapabilityTuple) GetTime() uint32 {
	if x != nil {
		return x.Time
	}
	return 0
}

type LongLivedGracefulRestartCapability struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Tuples []*LongLivedGracefulRestartCapabilityTuple `protobuf:"bytes,1,rep,name=tuples,proto3" json:"tuples,omitempty"`
}

func (x *LongLivedGracefulRestartCapability) Reset() {
	*x = LongLivedGracefulRestartCapability{}
	if protoimpl.UnsafeEnabled {
		mi := &file_capability_proto_msgTypes[12]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LongLivedGracefulRestartCapability) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LongLivedGracefulRestartCapability) ProtoMessage() {}

func (x *LongLivedGracefulRestartCapability) ProtoReflect() protoreflect.Message {
	mi := &file_capability_proto_msgTypes[12]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LongLivedGracefulRestartCapability.ProtoReflect.Descriptor instead.
func (*LongLivedGracefulRestartCapability) Descriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{12}
}

func (x *LongLivedGracefulRestartCapability) GetTuples() []*LongLivedGracefulRestartCapabilityTuple {
	if x != nil {
		return x.Tuples
	}
	return nil
}

type RouteRefreshCiscoCapability struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RouteRefreshCiscoCapability) Reset() {
	*x = RouteRefreshCiscoCapability{}
	if protoimpl.UnsafeEnabled {
		mi := &file_capability_proto_msgTypes[13]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RouteRefreshCiscoCapability) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RouteRefreshCiscoCapability) ProtoMessage() {}

func (x *RouteRefreshCiscoCapability) ProtoReflect() protoreflect.Message {
	mi := &file_capability_proto_msgTypes[13]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RouteRefreshCiscoCapability.ProtoReflect.Descriptor instead.
func (*RouteRefreshCiscoCapability) Descriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{13}
}

type UnknownCapability struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Code  uint32 `protobuf:"varint,1,opt,name=code,proto3" json:"code,omitempty"`
	Value []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *UnknownCapability) Reset() {
	*x = UnknownCapability{}
	if protoimpl.UnsafeEnabled {
		mi := &file_capability_proto_msgTypes[14]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UnknownCapability) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UnknownCapability) ProtoMessage() {}

func (x *UnknownCapability) ProtoReflect() protoreflect.Message {
	mi := &file_capability_proto_msgTypes[14]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UnknownCapability.ProtoReflect.Descriptor instead.
func (*UnknownCapability) Descriptor() ([]byte, []int) {
	return file_capability_proto_rawDescGZIP(), []int{14}
}

func (x *UnknownCapability) GetCode() uint32 {
	if x != nil {
		return x.Code
	}
	return 0
}

func (x *UnknownCapability) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

var File_capability_proto protoreflect.FileDescriptor

var file_capability_proto_rawDesc = []byte{
	0x0a, 0x10, 0x63, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x05, 0x61, 0x70, 0x69, 0x70, 0x62, 0x1a, 0x0b, 0x67, 0x6f, 0x62, 0x67, 0x70,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x40, 0x0a, 0x17, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x50,
	0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74,
	0x79, 0x12, 0x25, 0x0a, 0x06, 0x66, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x0d, 0x2e, 0x61, 0x70, 0x69, 0x70, 0x62, 0x2e, 0x46, 0x61, 0x6d, 0x69, 0x6c, 0x79,
	0x52, 0x06, 0x66, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x22, 0x18, 0x0a, 0x16, 0x52, 0x6f, 0x75, 0x74,
	0x65, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69,
	0x74, 0x79, 0x22, 0x1d, 0x0a, 0x1b, 0x43, 0x61, 0x72, 0x72, 0x79, 0x69, 0x6e, 0x67, 0x4c, 0x61,
	0x62, 0x65, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74,
	0x79, 0x22, 0x86, 0x01, 0x0a, 0x1e, 0x45, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x4e, 0x65,
	0x78, 0x74, 0x68, 0x6f, 0x70, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x54,
	0x75, 0x70, 0x6c, 0x65, 0x12, 0x2e, 0x0a, 0x0b, 0x6e, 0x6c, 0x72, 0x69, 0x5f, 0x66, 0x61, 0x6d,
	0x69, 0x6c, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x61, 0x70, 0x69, 0x70,
	0x62, 0x2e, 0x46, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x52, 0x0a, 0x6e, 0x6c, 0x72, 0x69, 0x46, 0x61,
	0x6d, 0x69, 0x6c, 0x79, 0x12, 0x34, 0x0a, 0x0e, 0x6e, 0x65, 0x78, 0x74, 0x68, 0x6f, 0x70, 0x5f,
	0x66, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x61,
	0x70, 0x69, 0x70, 0x62, 0x2e, 0x46, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x52, 0x0d, 0x6e, 0x65, 0x78,
	0x74, 0x68, 0x6f, 0x70, 0x46, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x22, 0x5a, 0x0a, 0x19, 0x45, 0x78,
	0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x4e, 0x65, 0x78, 0x74, 0x68, 0x6f, 0x70, 0x43, 0x61, 0x70,
	0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x12, 0x3d, 0x0a, 0x06, 0x74, 0x75, 0x70, 0x6c, 0x65,
	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x25, 0x2e, 0x61, 0x70, 0x69, 0x70, 0x62, 0x2e,
	0x45, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x4e, 0x65, 0x78, 0x74, 0x68, 0x6f, 0x70, 0x43,
	0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x54, 0x75, 0x70, 0x6c, 0x65, 0x52, 0x06,
	0x74, 0x75, 0x70, 0x6c, 0x65, 0x73, 0x22, 0x5d, 0x0a, 0x1e, 0x47, 0x72, 0x61, 0x63, 0x65, 0x66,
	0x75, 0x6c, 0x52, 0x65, 0x73, 0x74, 0x61, 0x72, 0x74, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c,
	0x69, 0x74, 0x79, 0x54, 0x75, 0x70, 0x6c, 0x65, 0x12, 0x25, 0x0a, 0x06, 0x66, 0x61, 0x6d, 0x69,
	0x6c, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x61, 0x70, 0x69, 0x70, 0x62,
	0x2e, 0x46, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x52, 0x06, 0x66, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x12,
	0x14, 0x0a, 0x05, 0x66, 0x6c, 0x61, 0x67, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05,
	0x66, 0x6c, 0x61, 0x67, 0x73, 0x22, 0x84, 0x01, 0x0a, 0x19, 0x47, 0x72, 0x61, 0x63, 0x65, 0x66,
	0x75, 0x6c, 0x52, 0x65, 0x73, 0x74, 0x61, 0x72, 0x74, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c,
	0x69, 0x74, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x66, 0x6c, 0x61, 0x67, 0x73, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x05, 0x66, 0x6c, 0x61, 0x67, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x69, 0x6d,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x3d, 0x0a,
	0x06, 0x74, 0x75, 0x70, 0x6c, 0x65, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x25, 0x2e,
	0x61, 0x70, 0x69, 0x70, 0x62, 0x2e, 0x47, 0x72, 0x61, 0x63, 0x65, 0x66, 0x75, 0x6c, 0x52, 0x65,
	0x73, 0x74, 0x61, 0x72, 0x74, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x54,
	0x75, 0x70, 0x6c, 0x65, 0x52, 0x06, 0x74, 0x75, 0x70, 0x6c, 0x65, 0x73, 0x22, 0x2d, 0x0a, 0x1b,
	0x46, 0x6f, 0x75, 0x72, 0x4f, 0x63, 0x74, 0x65, 0x74, 0x41, 0x53, 0x4e, 0x75, 0x6d, 0x62, 0x65,
	0x72, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x12, 0x0e, 0x0a, 0x02, 0x61,
	0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x02, 0x61, 0x73, 0x22, 0x67, 0x0a, 0x16, 0x41,
	0x64, 0x64, 0x50, 0x61, 0x74, 0x68, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79,
	0x54, 0x75, 0x70, 0x6c, 0x65, 0x12, 0x25, 0x0a, 0x06, 0x66, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x61, 0x70, 0x69, 0x70, 0x62, 0x2e, 0x46, 0x61,
	0x6d, 0x69, 0x6c, 0x79, 0x52, 0x06, 0x66, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x12, 0x26, 0x0a, 0x04,
	0x6d, 0x6f, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x12, 0x2e, 0x61, 0x70, 0x69,
	0x70, 0x62, 0x2e, 0x41, 0x64, 0x64, 0x50, 0x61, 0x74, 0x68, 0x4d, 0x6f, 0x64, 0x65, 0x52, 0x04,
	0x6d, 0x6f, 0x64, 0x65, 0x22, 0x4a, 0x0a, 0x11, 0x41, 0x64, 0x64, 0x50, 0x61, 0x74, 0x68, 0x43,
	0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x12, 0x35, 0x0a, 0x06, 0x74, 0x75, 0x70,
	0x6c, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x61, 0x70, 0x69, 0x70,
	0x62, 0x2e, 0x41, 0x64, 0x64, 0x50, 0x61, 0x74, 0x68, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c,
	0x69, 0x74, 0x79, 0x54, 0x75, 0x70, 0x6c, 0x65, 0x52, 0x06, 0x74, 0x75, 0x70, 0x6c, 0x65, 0x73,
	0x22, 0x20, 0x0a, 0x1e, 0x45, 0x6e, 0x68, 0x61, 0x6e, 0x63, 0x65, 0x64, 0x52, 0x6f, 0x75, 0x74,
	0x65, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69,
	0x74, 0x79, 0x22, 0x7a, 0x0a, 0x27, 0x4c, 0x6f, 0x6e, 0x67, 0x4c, 0x69, 0x76, 0x65, 0x64, 0x47,
	0x72, 0x61, 0x63, 0x65, 0x66, 0x75, 0x6c, 0x52, 0x65, 0x73, 0x74, 0x61, 0x72, 0x74, 0x43, 0x61,
	0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x54, 0x75, 0x70, 0x6c, 0x65, 0x12, 0x25, 0x0a,
	0x06, 0x66, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e,
	0x61, 0x70, 0x69, 0x70, 0x62, 0x2e, 0x46, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x52, 0x06, 0x66, 0x61,
	0x6d, 0x69, 0x6c, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x66, 0x6c, 0x61, 0x67, 0x73, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x05, 0x66, 0x6c, 0x61, 0x67, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x69,
	0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x74, 0x69, 0x6d, 0x65, 0x22, 0x6c,
	0x0a, 0x22, 0x4c, 0x6f, 0x6e, 0x67, 0x4c, 0x69, 0x76, 0x65, 0x64, 0x47, 0x72, 0x61, 0x63, 0x65,
	0x66, 0x75, 0x6c, 0x52, 0x65, 0x73, 0x74, 0x61, 0x72, 0x74, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69,
	0x6c, 0x69, 0x74, 0x79, 0x12, 0x46, 0x0a, 0x06, 0x74, 0x75, 0x70, 0x6c, 0x65, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x2e, 0x2e, 0x61, 0x70, 0x69, 0x70, 0x62, 0x2e, 0x4c, 0x6f, 0x6e,
	0x67, 0x4c, 0x69, 0x76, 0x65, 0x64, 0x47, 0x72, 0x61, 0x63, 0x65, 0x66, 0x75, 0x6c, 0x52, 0x65,
	0x73, 0x74, 0x61, 0x72, 0x74, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x54,
	0x75, 0x70, 0x6c, 0x65, 0x52, 0x06, 0x74, 0x75, 0x70, 0x6c, 0x65, 0x73, 0x22, 0x1d, 0x0a, 0x1b,
	0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x43, 0x69, 0x73, 0x63,
	0x6f, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x22, 0x3d, 0x0a, 0x11, 0x55,
	0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x43, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79,
	0x12, 0x12, 0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04,
	0x63, 0x6f, 0x64, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x2a, 0x4c, 0x0a, 0x0b, 0x41, 0x64,
	0x64, 0x50, 0x61, 0x74, 0x68, 0x4d, 0x6f, 0x64, 0x65, 0x12, 0x0d, 0x0a, 0x09, 0x4d, 0x4f, 0x44,
	0x45, 0x5f, 0x4e, 0x4f, 0x4e, 0x45, 0x10, 0x00, 0x12, 0x10, 0x0a, 0x0c, 0x4d, 0x4f, 0x44, 0x45,
	0x5f, 0x52, 0x45, 0x43, 0x45, 0x49, 0x56, 0x45, 0x10, 0x01, 0x12, 0x0d, 0x0a, 0x09, 0x4d, 0x4f,
	0x44, 0x45, 0x5f, 0x53, 0x45, 0x4e, 0x44, 0x10, 0x02, 0x12, 0x0d, 0x0a, 0x09, 0x4d, 0x4f, 0x44,
	0x45, 0x5f, 0x42, 0x4f, 0x54, 0x48, 0x10, 0x03, 0x42, 0x21, 0x5a, 0x1f, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x73, 0x72, 0x67, 0x2f, 0x67, 0x6f, 0x62, 0x67,
	0x70, 0x2f, 0x61, 0x70, 0x69, 0x3b, 0x61, 0x70, 0x69, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_capability_proto_rawDescOnce sync.Once
	file_capability_proto_rawDescData = file_capability_proto_rawDesc
)

func file_capability_proto_rawDescGZIP() []byte {
	file_capability_proto_rawDescOnce.Do(func() {
		file_capability_proto_rawDescData = protoimpl.X.CompressGZIP(file_capability_proto_rawDescData)
	})
	return file_capability_proto_rawDescData
}

var file_capability_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_capability_proto_msgTypes = make([]protoimpl.MessageInfo, 15)
var file_capability_proto_goTypes = []interface{}{
	(AddPathMode)(0),                                // 0: apipb.AddPathMode
	(*MultiProtocolCapability)(nil),                 // 1: apipb.MultiProtocolCapability
	(*RouteRefreshCapability)(nil),                  // 2: apipb.RouteRefreshCapability
	(*CarryingLabelInfoCapability)(nil),             // 3: apipb.CarryingLabelInfoCapability
	(*ExtendedNexthopCapabilityTuple)(nil),          // 4: apipb.ExtendedNexthopCapabilityTuple
	(*ExtendedNexthopCapability)(nil),               // 5: apipb.ExtendedNexthopCapability
	(*GracefulRestartCapabilityTuple)(nil),          // 6: apipb.GracefulRestartCapabilityTuple
	(*GracefulRestartCapability)(nil),               // 7: apipb.GracefulRestartCapability
	(*FourOctetASNumberCapability)(nil),             // 8: apipb.FourOctetASNumberCapability
	(*AddPathCapabilityTuple)(nil),                  // 9: apipb.AddPathCapabilityTuple
	(*AddPathCapability)(nil),                       // 10: apipb.AddPathCapability
	(*EnhancedRouteRefreshCapability)(nil),          // 11: apipb.EnhancedRouteRefreshCapability
	(*LongLivedGracefulRestartCapabilityTuple)(nil), // 12: apipb.LongLivedGracefulRestartCapabilityTuple
	(*LongLivedGracefulRestartCapability)(nil),      // 13: apipb.LongLivedGracefulRestartCapability
	(*RouteRefreshCiscoCapability)(nil),             // 14: apipb.RouteRefreshCiscoCapability
	(*UnknownCapability)(nil),                       // 15: apipb.UnknownCapability
	(*Family)(nil),                                  // 16: apipb.Family
}
var file_capability_proto_depIdxs = []int32{
	16, // 0: apipb.MultiProtocolCapability.family:type_name -> apipb.Family
	16, // 1: apipb.ExtendedNexthopCapabilityTuple.nlri_family:type_name -> apipb.Family
	16, // 2: apipb.ExtendedNexthopCapabilityTuple.nexthop_family:type_name -> apipb.Family
	4,  // 3: apipb.ExtendedNexthopCapability.tuples:type_name -> apipb.ExtendedNexthopCapabilityTuple
	16, // 4: apipb.GracefulRestartCapabilityTuple.family:type_name -> apipb.Family
	6,  // 5: apipb.GracefulRestartCapability.tuples:type_name -> apipb.GracefulRestartCapabilityTuple
	16, // 6: apipb.AddPathCapabilityTuple.family:type_name -> apipb.Family
	0,  // 7: apipb.AddPathCapabilityTuple.mode:type_name -> apipb.AddPathMode
	9,  // 8: apipb.AddPathCapability.tuples:type_name -> apipb.AddPathCapabilityTuple
	16, // 9: apipb.LongLivedGracefulRestartCapabilityTuple.family:type_name -> apipb.Family
	12, // 10: apipb.LongLivedGracefulRestartCapability.tuples:type_name -> apipb.LongLivedGracefulRestartCapabilityTuple
	11, // [11:11] is the sub-list for method output_type
	11, // [11:11] is the sub-list for method input_type
	11, // [11:11] is the sub-list for extension type_name
	11, // [11:11] is the sub-list for extension extendee
	0,  // [0:11] is the sub-list for field type_name
}

func init() { file_capability_proto_init() }
func file_capability_proto_init() {
	if File_capability_proto != nil {
		return
	}
	file_gobgp_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_capability_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MultiProtocolCapability); i {
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
		file_capability_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RouteRefreshCapability); i {
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
		file_capability_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CarryingLabelInfoCapability); i {
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
		file_capability_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExtendedNexthopCapabilityTuple); i {
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
		file_capability_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExtendedNexthopCapability); i {
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
		file_capability_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GracefulRestartCapabilityTuple); i {
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
		file_capability_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GracefulRestartCapability); i {
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
		file_capability_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FourOctetASNumberCapability); i {
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
		file_capability_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AddPathCapabilityTuple); i {
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
		file_capability_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AddPathCapability); i {
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
		file_capability_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EnhancedRouteRefreshCapability); i {
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
		file_capability_proto_msgTypes[11].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LongLivedGracefulRestartCapabilityTuple); i {
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
		file_capability_proto_msgTypes[12].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LongLivedGracefulRestartCapability); i {
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
		file_capability_proto_msgTypes[13].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RouteRefreshCiscoCapability); i {
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
		file_capability_proto_msgTypes[14].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UnknownCapability); i {
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
			RawDescriptor: file_capability_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   15,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_capability_proto_goTypes,
		DependencyIndexes: file_capability_proto_depIdxs,
		EnumInfos:         file_capability_proto_enumTypes,
		MessageInfos:      file_capability_proto_msgTypes,
	}.Build()
	File_capability_proto = out.File
	file_capability_proto_rawDesc = nil
	file_capability_proto_goTypes = nil
	file_capability_proto_depIdxs = nil
}
