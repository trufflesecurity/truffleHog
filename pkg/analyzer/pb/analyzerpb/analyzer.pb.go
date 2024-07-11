// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v4.25.3
// source: analyzer.proto

package analyzerpb

import (
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

type SecretType int32

const (
	SecretType_INVALID     SecretType = 0
	SecretType_AIRBRAKE    SecretType = 1
	SecretType_ASANA       SecretType = 2
	SecretType_BITBUCKET   SecretType = 3
	SecretType_GITHUB      SecretType = 4
	SecretType_GITLAB      SecretType = 5
	SecretType_HUGGINGFACE SecretType = 6
	SecretType_MAILCHIMP   SecretType = 7
	SecretType_MAILGUN     SecretType = 8
	SecretType_MYSQL       SecretType = 9
	SecretType_OPENAI      SecretType = 10
	SecretType_OPSGENIE    SecretType = 11
	SecretType_POSTGRES    SecretType = 12
	SecretType_POSTMAN     SecretType = 13
	SecretType_SENDGRID    SecretType = 14
	SecretType_SHOPIFY     SecretType = 15
	SecretType_SLACK       SecretType = 16
	SecretType_SOURCEGRAPH SecretType = 17
	SecretType_SQUARE      SecretType = 18
	SecretType_STRIPE      SecretType = 19
	SecretType_TWILIO      SecretType = 20
)

// Enum value maps for SecretType.
var (
	SecretType_name = map[int32]string{
		0:  "INVALID",
		1:  "AIRBRAKE",
		2:  "ASANA",
		3:  "BITBUCKET",
		4:  "GITHUB",
		5:  "GITLAB",
		6:  "HUGGINGFACE",
		7:  "MAILCHIMP",
		8:  "MAILGUN",
		9:  "MYSQL",
		10: "OPENAI",
		11: "OPSGENIE",
		12: "POSTGRES",
		13: "POSTMAN",
		14: "SENDGRID",
		15: "SHOPIFY",
		16: "SLACK",
		17: "SOURCEGRAPH",
		18: "SQUARE",
		19: "STRIPE",
		20: "TWILIO",
	}
	SecretType_value = map[string]int32{
		"INVALID":     0,
		"AIRBRAKE":    1,
		"ASANA":       2,
		"BITBUCKET":   3,
		"GITHUB":      4,
		"GITLAB":      5,
		"HUGGINGFACE": 6,
		"MAILCHIMP":   7,
		"MAILGUN":     8,
		"MYSQL":       9,
		"OPENAI":      10,
		"OPSGENIE":    11,
		"POSTGRES":    12,
		"POSTMAN":     13,
		"SENDGRID":    14,
		"SHOPIFY":     15,
		"SLACK":       16,
		"SOURCEGRAPH": 17,
		"SQUARE":      18,
		"STRIPE":      19,
		"TWILIO":      20,
	}
)

func (x SecretType) Enum() *SecretType {
	p := new(SecretType)
	*p = x
	return p
}

func (x SecretType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SecretType) Descriptor() protoreflect.EnumDescriptor {
	return file_analyzer_proto_enumTypes[0].Descriptor()
}

func (SecretType) Type() protoreflect.EnumType {
	return &file_analyzer_proto_enumTypes[0]
}

func (x SecretType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SecretType.Descriptor instead.
func (SecretType) EnumDescriptor() ([]byte, []int) {
	return file_analyzer_proto_rawDescGZIP(), []int{0}
}

var File_analyzer_proto protoreflect.FileDescriptor

var file_analyzer_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x08, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x72, 0x2a, 0xa1, 0x02, 0x0a, 0x0a, 0x53,
	0x65, 0x63, 0x72, 0x65, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x49, 0x4e, 0x56,
	0x41, 0x4c, 0x49, 0x44, 0x10, 0x00, 0x12, 0x0c, 0x0a, 0x08, 0x41, 0x49, 0x52, 0x42, 0x52, 0x41,
	0x4b, 0x45, 0x10, 0x01, 0x12, 0x09, 0x0a, 0x05, 0x41, 0x53, 0x41, 0x4e, 0x41, 0x10, 0x02, 0x12,
	0x0d, 0x0a, 0x09, 0x42, 0x49, 0x54, 0x42, 0x55, 0x43, 0x4b, 0x45, 0x54, 0x10, 0x03, 0x12, 0x0a,
	0x0a, 0x06, 0x47, 0x49, 0x54, 0x48, 0x55, 0x42, 0x10, 0x04, 0x12, 0x0a, 0x0a, 0x06, 0x47, 0x49,
	0x54, 0x4c, 0x41, 0x42, 0x10, 0x05, 0x12, 0x0f, 0x0a, 0x0b, 0x48, 0x55, 0x47, 0x47, 0x49, 0x4e,
	0x47, 0x46, 0x41, 0x43, 0x45, 0x10, 0x06, 0x12, 0x0d, 0x0a, 0x09, 0x4d, 0x41, 0x49, 0x4c, 0x43,
	0x48, 0x49, 0x4d, 0x50, 0x10, 0x07, 0x12, 0x0b, 0x0a, 0x07, 0x4d, 0x41, 0x49, 0x4c, 0x47, 0x55,
	0x4e, 0x10, 0x08, 0x12, 0x09, 0x0a, 0x05, 0x4d, 0x59, 0x53, 0x51, 0x4c, 0x10, 0x09, 0x12, 0x0a,
	0x0a, 0x06, 0x4f, 0x50, 0x45, 0x4e, 0x41, 0x49, 0x10, 0x0a, 0x12, 0x0c, 0x0a, 0x08, 0x4f, 0x50,
	0x53, 0x47, 0x45, 0x4e, 0x49, 0x45, 0x10, 0x0b, 0x12, 0x0c, 0x0a, 0x08, 0x50, 0x4f, 0x53, 0x54,
	0x47, 0x52, 0x45, 0x53, 0x10, 0x0c, 0x12, 0x0b, 0x0a, 0x07, 0x50, 0x4f, 0x53, 0x54, 0x4d, 0x41,
	0x4e, 0x10, 0x0d, 0x12, 0x0c, 0x0a, 0x08, 0x53, 0x45, 0x4e, 0x44, 0x47, 0x52, 0x49, 0x44, 0x10,
	0x0e, 0x12, 0x0b, 0x0a, 0x07, 0x53, 0x48, 0x4f, 0x50, 0x49, 0x46, 0x59, 0x10, 0x0f, 0x12, 0x09,
	0x0a, 0x05, 0x53, 0x4c, 0x41, 0x43, 0x4b, 0x10, 0x10, 0x12, 0x0f, 0x0a, 0x0b, 0x53, 0x4f, 0x55,
	0x52, 0x43, 0x45, 0x47, 0x52, 0x41, 0x50, 0x48, 0x10, 0x11, 0x12, 0x0a, 0x0a, 0x06, 0x53, 0x51,
	0x55, 0x41, 0x52, 0x45, 0x10, 0x12, 0x12, 0x0a, 0x0a, 0x06, 0x53, 0x54, 0x52, 0x49, 0x50, 0x45,
	0x10, 0x13, 0x12, 0x0a, 0x0a, 0x06, 0x54, 0x57, 0x49, 0x4c, 0x49, 0x4f, 0x10, 0x14, 0x42, 0x45,
	0x5a, 0x43, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x74, 0x72, 0x75,
	0x66, 0x66, 0x6c, 0x65, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2f, 0x74, 0x72, 0x75,
	0x66, 0x66, 0x6c, 0x65, 0x68, 0x6f, 0x67, 0x2f, 0x76, 0x33, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x61,
	0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x72, 0x2f, 0x70, 0x62, 0x2f, 0x61, 0x6e, 0x61, 0x6c, 0x79,
	0x7a, 0x65, 0x72, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_analyzer_proto_rawDescOnce sync.Once
	file_analyzer_proto_rawDescData = file_analyzer_proto_rawDesc
)

func file_analyzer_proto_rawDescGZIP() []byte {
	file_analyzer_proto_rawDescOnce.Do(func() {
		file_analyzer_proto_rawDescData = protoimpl.X.CompressGZIP(file_analyzer_proto_rawDescData)
	})
	return file_analyzer_proto_rawDescData
}

var file_analyzer_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_analyzer_proto_goTypes = []interface{}{
	(SecretType)(0), // 0: analyzer.SecretType
}
var file_analyzer_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_analyzer_proto_init() }
func file_analyzer_proto_init() {
	if File_analyzer_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_analyzer_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_analyzer_proto_goTypes,
		DependencyIndexes: file_analyzer_proto_depIdxs,
		EnumInfos:         file_analyzer_proto_enumTypes,
	}.Build()
	File_analyzer_proto = out.File
	file_analyzer_proto_rawDesc = nil
	file_analyzer_proto_goTypes = nil
	file_analyzer_proto_depIdxs = nil
}
