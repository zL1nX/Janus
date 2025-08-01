/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: janus_audit.proto */

#ifndef PROTOBUF_C_janus_5faudit_2eproto__INCLUDED
#define PROTOBUF_C_janus_5faudit_2eproto__INCLUDED

#include "protobuf-c.h"

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _AuditRequest AuditRequest;
typedef struct _AuditCredential AuditCredential;
typedef struct _AuditResult AuditResult;


/* --- enums --- */


/* --- messages --- */

struct  _AuditRequest
{
  ProtobufCMessage base;
  size_t n_ssid;
  char **ssid;
  uint32_t flag;
  char *audit_id;
  char *aid;
  char *vid;
};
#define AUDIT_REQUEST__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&audit_request__descriptor) \
    , 0,NULL, 0, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string }


struct  _AuditCredential
{
  ProtobufCMessage base;
  char *nonce;
  char *credential;
  char *aid;
  char *vid;
  char *ssid;
};
#define AUDIT_CREDENTIAL__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&audit_credential__descriptor) \
    , (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string }


struct  _AuditResult
{
  ProtobufCMessage base;
  uint32_t result;
  char *ssid;
};
#define AUDIT_RESULT__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&audit_result__descriptor) \
    , 0, (char *)protobuf_c_empty_string }


/* AuditRequest methods */
void   audit_request__init
                     (AuditRequest         *message);
size_t audit_request__get_packed_size
                     (const AuditRequest   *message);
size_t audit_request__pack
                     (const AuditRequest   *message,
                      uint8_t             *out);
size_t audit_request__pack_to_buffer
                     (const AuditRequest   *message,
                      ProtobufCBuffer     *buffer);
AuditRequest *
       audit_request__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   audit_request__free_unpacked
                     (AuditRequest *message,
                      ProtobufCAllocator *allocator);
/* AuditCredential methods */
void   audit_credential__init
                     (AuditCredential         *message);
size_t audit_credential__get_packed_size
                     (const AuditCredential   *message);
size_t audit_credential__pack
                     (const AuditCredential   *message,
                      uint8_t             *out);
size_t audit_credential__pack_to_buffer
                     (const AuditCredential   *message,
                      ProtobufCBuffer     *buffer);
AuditCredential *
       audit_credential__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   audit_credential__free_unpacked
                     (AuditCredential *message,
                      ProtobufCAllocator *allocator);
/* AuditResult methods */
void   audit_result__init
                     (AuditResult         *message);
size_t audit_result__get_packed_size
                     (const AuditResult   *message);
size_t audit_result__pack
                     (const AuditResult   *message,
                      uint8_t             *out);
size_t audit_result__pack_to_buffer
                     (const AuditResult   *message,
                      ProtobufCBuffer     *buffer);
AuditResult *
       audit_result__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   audit_result__free_unpacked
                     (AuditResult *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*AuditRequest_Closure)
                 (const AuditRequest *message,
                  void *closure_data);
typedef void (*AuditCredential_Closure)
                 (const AuditCredential *message,
                  void *closure_data);
typedef void (*AuditResult_Closure)
                 (const AuditResult *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor audit_request__descriptor;
extern const ProtobufCMessageDescriptor audit_credential__descriptor;
extern const ProtobufCMessageDescriptor audit_result__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_janus_5faudit_2eproto__INCLUDED */
