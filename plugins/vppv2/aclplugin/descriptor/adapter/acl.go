// Code generated by adapter-generator. DO NOT EDIT.

package adapter

import (
	"github.com/gogo/protobuf/proto"
	. "github.com/ligato/vpp-agent/plugins/kvscheduler/api"
	"github.com/ligato/vpp-agent/plugins/vppv2/aclplugin/aclidx"
	"github.com/ligato/vpp-agent/api/models/vpp/acl"
)

////////// type-safe key-value pair with metadata //////////

type ACLKVWithMetadata struct {
	Key      string
	Value    *vpp_acl.Acl
	Metadata *aclidx.ACLMetadata
	Origin   ValueOrigin
}

////////// type-safe Descriptor structure //////////

type ACLDescriptor struct {
	Name               string
	KeySelector        KeySelector
	ValueTypeName      string
	KeyLabel           func(key string) string
	ValueComparator    func(key string, oldValue, newValue *vpp_acl.Acl) bool
	NBKeyPrefix        string
	WithMetadata       bool
	MetadataMapFactory MetadataMapFactory
	Add                func(key string, value *vpp_acl.Acl) (metadata *aclidx.ACLMetadata, err error)
	Delete             func(key string, value *vpp_acl.Acl, metadata *aclidx.ACLMetadata) error
	Modify             func(key string, oldValue, newValue *vpp_acl.Acl, oldMetadata *aclidx.ACLMetadata) (newMetadata *aclidx.ACLMetadata, err error)
	ModifyWithRecreate func(key string, oldValue, newValue *vpp_acl.Acl, metadata *aclidx.ACLMetadata) bool
	Update             func(key string, value *vpp_acl.Acl, metadata *aclidx.ACLMetadata) error
	IsRetriableFailure func(err error) bool
	Dependencies       func(key string, value *vpp_acl.Acl) []Dependency
	DerivedValues      func(key string, value *vpp_acl.Acl) []KeyValuePair
	Dump               func(correlate []ACLKVWithMetadata) ([]ACLKVWithMetadata, error)
	DumpDependencies   []string /* descriptor name */
}

////////// Descriptor adapter //////////

type ACLDescriptorAdapter struct {
	descriptor *ACLDescriptor
}

func NewACLDescriptor(typedDescriptor *ACLDescriptor) *KVDescriptor {
	adapter := &ACLDescriptorAdapter{descriptor: typedDescriptor}
	descriptor := &KVDescriptor{
		Name:               typedDescriptor.Name,
		KeySelector:        typedDescriptor.KeySelector,
		ValueTypeName:      typedDescriptor.ValueTypeName,
		KeyLabel:           typedDescriptor.KeyLabel,
		NBKeyPrefix:        typedDescriptor.NBKeyPrefix,
		WithMetadata:       typedDescriptor.WithMetadata,
		MetadataMapFactory: typedDescriptor.MetadataMapFactory,
		IsRetriableFailure: typedDescriptor.IsRetriableFailure,
		DumpDependencies:   typedDescriptor.DumpDependencies,
	}
	if typedDescriptor.ValueComparator != nil {
		descriptor.ValueComparator = adapter.ValueComparator
	}
	if typedDescriptor.Add != nil {
		descriptor.Add = adapter.Add
	}
	if typedDescriptor.Delete != nil {
		descriptor.Delete = adapter.Delete
	}
	if typedDescriptor.Modify != nil {
		descriptor.Modify = adapter.Modify
	}
	if typedDescriptor.ModifyWithRecreate != nil {
		descriptor.ModifyWithRecreate = adapter.ModifyWithRecreate
	}
	if typedDescriptor.Update != nil {
		descriptor.Update = adapter.Update
	}
	if typedDescriptor.Dependencies != nil {
		descriptor.Dependencies = adapter.Dependencies
	}
	if typedDescriptor.DerivedValues != nil {
		descriptor.DerivedValues = adapter.DerivedValues
	}
	if typedDescriptor.Dump != nil {
		descriptor.Dump = adapter.Dump
	}
	return descriptor
}

func (da *ACLDescriptorAdapter) ValueComparator(key string, oldValue, newValue proto.Message) bool {
	typedOldValue, err1 := castACLValue(key, oldValue)
	typedNewValue, err2 := castACLValue(key, newValue)
	if err1 != nil || err2 != nil {
		return false
	}
	return da.descriptor.ValueComparator(key, typedOldValue, typedNewValue)
}

func (da *ACLDescriptorAdapter) Add(key string, value proto.Message) (metadata Metadata, err error) {
	typedValue, err := castACLValue(key, value)
	if err != nil {
		return nil, err
	}
	return da.descriptor.Add(key, typedValue)
}

func (da *ACLDescriptorAdapter) Modify(key string, oldValue, newValue proto.Message, oldMetadata Metadata) (newMetadata Metadata, err error) {
	oldTypedValue, err := castACLValue(key, oldValue)
	if err != nil {
		return nil, err
	}
	newTypedValue, err := castACLValue(key, newValue)
	if err != nil {
		return nil, err
	}
	typedOldMetadata, err := castACLMetadata(key, oldMetadata)
	if err != nil {
		return nil, err
	}
	return da.descriptor.Modify(key, oldTypedValue, newTypedValue, typedOldMetadata)
}

func (da *ACLDescriptorAdapter) Delete(key string, value proto.Message, metadata Metadata) error {
	typedValue, err := castACLValue(key, value)
	if err != nil {
		return err
	}
	typedMetadata, err := castACLMetadata(key, metadata)
	if err != nil {
		return err
	}
	return da.descriptor.Delete(key, typedValue, typedMetadata)
}

func (da *ACLDescriptorAdapter) ModifyWithRecreate(key string, oldValue, newValue proto.Message, metadata Metadata) bool {
	oldTypedValue, err := castACLValue(key, oldValue)
	if err != nil {
		return true
	}
	newTypedValue, err := castACLValue(key, newValue)
	if err != nil {
		return true
	}
	typedMetadata, err := castACLMetadata(key, metadata)
	if err != nil {
		return true
	}
	return da.descriptor.ModifyWithRecreate(key, oldTypedValue, newTypedValue, typedMetadata)
}

func (da *ACLDescriptorAdapter) Update(key string, value proto.Message, metadata Metadata) error {
	typedValue, err := castACLValue(key, value)
	if err != nil {
		return err
	}
	typedMetadata, err := castACLMetadata(key, metadata)
	if err != nil {
		return err
	}
	return da.descriptor.Update(key, typedValue, typedMetadata)
}

func (da *ACLDescriptorAdapter) Dependencies(key string, value proto.Message) []Dependency {
	typedValue, err := castACLValue(key, value)
	if err != nil {
		return nil
	}
	return da.descriptor.Dependencies(key, typedValue)
}

func (da *ACLDescriptorAdapter) DerivedValues(key string, value proto.Message) []KeyValuePair {
	typedValue, err := castACLValue(key, value)
	if err != nil {
		return nil
	}
	return da.descriptor.DerivedValues(key, typedValue)
}

func (da *ACLDescriptorAdapter) Dump(correlate []KVWithMetadata) ([]KVWithMetadata, error) {
	var correlateWithType []ACLKVWithMetadata
	for _, kvpair := range correlate {
		typedValue, err := castACLValue(kvpair.Key, kvpair.Value)
		if err != nil {
			continue
		}
		typedMetadata, err := castACLMetadata(kvpair.Key, kvpair.Metadata)
		if err != nil {
			continue
		}
		correlateWithType = append(correlateWithType,
			ACLKVWithMetadata{
				Key:      kvpair.Key,
				Value:    typedValue,
				Metadata: typedMetadata,
				Origin:   kvpair.Origin,
			})
	}

	typedDump, err := da.descriptor.Dump(correlateWithType)
	if err != nil {
		return nil, err
	}
	var dump []KVWithMetadata
	for _, typedKVWithMetadata := range typedDump {
		kvWithMetadata := KVWithMetadata{
			Key:      typedKVWithMetadata.Key,
			Metadata: typedKVWithMetadata.Metadata,
			Origin:   typedKVWithMetadata.Origin,
		}
		kvWithMetadata.Value = typedKVWithMetadata.Value
		dump = append(dump, kvWithMetadata)
	}
	return dump, err
}

////////// Helper methods //////////

func castACLValue(key string, value proto.Message) (*vpp_acl.Acl, error) {
	typedValue, ok := value.(*vpp_acl.Acl)
	if !ok {
		return nil, ErrInvalidValueType(key, value)
	}
	return typedValue, nil
}

func castACLMetadata(key string, metadata Metadata) (*aclidx.ACLMetadata, error) {
	if metadata == nil {
		return nil, nil
	}
	typedMetadata, ok := metadata.(*aclidx.ACLMetadata)
	if !ok {
		return nil, ErrInvalidMetadataType(key)
	}
	return typedMetadata, nil
}
