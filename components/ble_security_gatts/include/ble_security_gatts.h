#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define A2URPS_HT_MEAS_MAX_LEN            (13)

#define A2URPS_MANDATORY_MASK             (0x0F)
#define A2URPS_BODY_SENSOR_LOC_MASK       (0x30)
#define A2URPS_HR_CTNL_PT_MASK            (0xC0)

///Attributes State Machine
enum
{
    A2URS_IDX_SVC,

    A2URS_IDX_HR_MEAS_CHAR,
    A2URS_IDX_HR_MEAS_VAL,
    A2URS_IDX_HR_MEAS_NTF_CFG,

    A2URS_IDX_BOBY_SENSOR_LOC_CHAR,
    A2URS_IDX_BOBY_SENSOR_LOC_VAL,

    A2URS_IDX_HR_CTNL_PT_CHAR,
    A2URS_IDX_HR_CTNL_PT_VAL,

    A2URS_IDX_NB,
};

void start_security_BLE();
