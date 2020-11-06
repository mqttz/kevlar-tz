#ifndef __MQTTZ_TA_H__
#define __MQTTZ_TA_H__

/* UUID of the trusted application */
#define TA_MQTTZ_UUID \
        { 0x0757c01f, 0xbb1f, 0x4234, \
                { 0x9c, 0x1b, 0x5f, 0x61, 0x51, 0x5e, 0x69, 0xba } }

#define TA_MQTTZ_ID_SZ          12
#define TA_MQTTZ_AES_KEY_SZ     32
#define TA_MQTTZ_AES_IV_SZ      16
#define TA_MQTTZ_MAX_MSG_SZ     1024

#define TA_TCP_IP               "127.0.0.1"
#define TA_TCP_PORT             9999
#define TA_TCP_MAX_PKG_SZ       TA_MQTTZ_MAX_MSG_SZ + TA_MQTTZ_ID_SZ*2 + TA_MQTTZ_AES_IV_SZ + 4

#define TA_CACHE_SZ             128
#define TA_CACHE_HASH_SZ        128

#define TA_CACHE_POLICY_LRU     0
#define TA_CACHE_POLICY_FIFO    1

/*
 * TA_MQTTZ - MQT-TZ helper TA
 * param[0] unused
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_MQTTZ                0

#endif /* __MQTTZ_TA_H */
