/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: janus_audit.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "janus_audit.pb-c.h"
void   audit_request__init
                     (AuditRequest         *message)
{
  static const AuditRequest init_value = AUDIT_REQUEST__INIT;
  *message = init_value;
}
size_t audit_request__get_packed_size
                     (const AuditRequest *message)
{
  assert(message->base.descriptor == &audit_request__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t audit_request__pack
                     (const AuditRequest *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &audit_request__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t audit_request__pack_to_buffer
                     (const AuditRequest *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &audit_request__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
AuditRequest *
       audit_request__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (AuditRequest *)
     protobuf_c_message_unpack (&audit_request__descriptor,
                                allocator, len, data);
}
void   audit_request__free_unpacked
                     (AuditRequest *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &audit_request__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   audit_credential__init
                     (AuditCredential         *message)
{
  static const AuditCredential init_value = AUDIT_CREDENTIAL__INIT;
  *message = init_value;
}
size_t audit_credential__get_packed_size
                     (const AuditCredential *message)
{
  assert(message->base.descriptor == &audit_credential__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t audit_credential__pack
                     (const AuditCredential *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &audit_credential__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t audit_credential__pack_to_buffer
                     (const AuditCredential *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &audit_credential__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
AuditCredential *
       audit_credential__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (AuditCredential *)
     protobuf_c_message_unpack (&audit_credential__descriptor,
                                allocator, len, data);
}
void   audit_credential__free_unpacked
                     (AuditCredential *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &audit_credential__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   audit_result__init
                     (AuditResult         *message)
{
  static const AuditResult init_value = AUDIT_RESULT__INIT;
  *message = init_value;
}
size_t audit_result__get_packed_size
                     (const AuditResult *message)
{
  assert(message->base.descriptor == &audit_result__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t audit_result__pack
                     (const AuditResult *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &audit_result__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t audit_result__pack_to_buffer
                     (const AuditResult *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &audit_result__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
AuditResult *
       audit_result__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (AuditResult *)
     protobuf_c_message_unpack (&audit_result__descriptor,
                                allocator, len, data);
}
void   audit_result__free_unpacked
                     (AuditResult *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &audit_result__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor audit_request__field_descriptors[5] =
{
  {
    "ssid",
    1,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_STRING,
    offsetof(AuditRequest, n_ssid),
    offsetof(AuditRequest, ssid),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "flag",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(AuditRequest, flag),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "audit_id",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(AuditRequest, audit_id),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "aid",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(AuditRequest, aid),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "vid",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(AuditRequest, vid),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned audit_request__field_indices_by_name[] = {
  3,   /* field[3] = aid */
  2,   /* field[2] = audit_id */
  1,   /* field[1] = flag */
  0,   /* field[0] = ssid */
  4,   /* field[4] = vid */
};
static const ProtobufCIntRange audit_request__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor audit_request__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "AuditRequest",
  "AuditRequest",
  "AuditRequest",
  "",
  sizeof(AuditRequest),
  5,
  audit_request__field_descriptors,
  audit_request__field_indices_by_name,
  1,  audit_request__number_ranges,
  (ProtobufCMessageInit) audit_request__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor audit_credential__field_descriptors[5] =
{
  {
    "nonce",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(AuditCredential, nonce),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "credential",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(AuditCredential, credential),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "aid",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(AuditCredential, aid),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "vid",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(AuditCredential, vid),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ssid",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(AuditCredential, ssid),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned audit_credential__field_indices_by_name[] = {
  2,   /* field[2] = aid */
  1,   /* field[1] = credential */
  0,   /* field[0] = nonce */
  4,   /* field[4] = ssid */
  3,   /* field[3] = vid */
};
static const ProtobufCIntRange audit_credential__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor audit_credential__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "AuditCredential",
  "AuditCredential",
  "AuditCredential",
  "",
  sizeof(AuditCredential),
  5,
  audit_credential__field_descriptors,
  audit_credential__field_indices_by_name,
  1,  audit_credential__number_ranges,
  (ProtobufCMessageInit) audit_credential__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor audit_result__field_descriptors[2] =
{
  {
    "result",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(AuditResult, result),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ssid",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(AuditResult, ssid),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned audit_result__field_indices_by_name[] = {
  0,   /* field[0] = result */
  1,   /* field[1] = ssid */
};
static const ProtobufCIntRange audit_result__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor audit_result__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "AuditResult",
  "AuditResult",
  "AuditResult",
  "",
  sizeof(AuditResult),
  2,
  audit_result__field_descriptors,
  audit_result__field_indices_by_name,
  1,  audit_result__number_ranges,
  (ProtobufCMessageInit) audit_result__init,
  NULL,NULL,NULL    /* reserved[123] */
};
