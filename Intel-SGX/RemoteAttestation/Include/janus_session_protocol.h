#ifndef _JANUS_SESSION_PROROCOL_H
#define _JANUS_SESSION_PROROCOL_H

#include "janus_datatype.h"

//Session information structure
typedef struct _ra_janus_session_t
{
    uint32_t  session_id; //Identifies the current session
    uint32_t  status; //Indicates session is in progress, active or closed
    union
    {
        struct
        {
            janus_ra_msg_t janus_session;
        }in_progress;

        struct
        {
            // sgx_key_128bit_t AEK; //Session Key
            uint32_t counter; //Used to store Message Sequence Number
        }active;
    };
} janus_session_t;


#endif
