#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <mqttz_ta.h>

#define TA_UUID             TA_MQTTZ_UUID

#define TA_FLAGS            TA_FLAG_EXEC_DDR
#define TA_STACK_SIZE       (2 * 1024 * 1024)
#define TA_DATA_SIZE        (4 * 1024 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
        "Helper TA for MQT-TZ broker" }, \
    { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } }

#endif /*USER_TA_HEADER_DEFINES_H*/
