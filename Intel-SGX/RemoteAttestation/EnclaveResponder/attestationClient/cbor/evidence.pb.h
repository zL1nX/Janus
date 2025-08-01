/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.6-dev */

#ifndef PB_EVIDENCE_PB_H_INCLUDED
#define PB_EVIDENCE_PB_H_INCLUDED
#include "../pb.h"

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

/* Struct definitions */
typedef struct _Evidence {
    pb_callback_t ProverIdentity;
    pb_callback_t BlockID;
    pb_callback_t Measurement;
} Evidence;


#ifdef __cplusplus
extern "C" {
#endif

/* Initializer values for message structs */
#define Evidence_init_default                    {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define Evidence_init_zero                       {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}

/* Field tags (for use in manual encoding/decoding) */
#define Evidence_ProverIdentity_tag              1
#define Evidence_BlockID_tag                     2
#define Evidence_Measurement_tag                 3

/* Struct field encoding specification for nanopb */
#define Evidence_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, STRING,   ProverIdentity,    1) \
X(a, CALLBACK, SINGULAR, STRING,   BlockID,           2) \
X(a, CALLBACK, SINGULAR, STRING,   Measurement,       3)
#define Evidence_CALLBACK pb_default_field_callback
#define Evidence_DEFAULT NULL

extern const pb_msgdesc_t Evidence_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define Evidence_fields &Evidence_msg

/* Maximum encoded size of messages (where known) */
/* Evidence_size depends on runtime parameters */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
