/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if (__ARM_FEATURE_CMSE & 1) == 0
#error "Need ARMv8-M security extensions"
#elif (__ARM_FEATURE_CMSE & 2) == 0
#error "Compile with --cmse"
#endif

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "arm_cmse.h"
#include "board.h"
#include "veneer_table.h"
#include "tzm_config.h"

#include "pin_mux.h"
#include "clock_config.h"
#include "fsl_power.h"
#include "attrmgr.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define DEMO_CODE_START_NS 0x00050000
#define AHB_LAYERS_COUNT 12U
#define NON_SECURE_START DEMO_CODE_START_NS

/* typedef for non-secure callback functions */
typedef void (*funcptr_ns)(void) __attribute__((cmse_nonsecure_call));

typedef union
{
    struct ahb_secure_fault_info
    {
        unsigned access_type : 2;
        unsigned reserved0 : 2;
        unsigned master_sec_level : 2;
        unsigned antipol_master_sec_level : 2;
        unsigned master_number : 4;
        unsigned reserved : 20;
    } fault_info;
    unsigned value;
} ahb_secure_fault_info_t;

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Global variables
 ******************************************************************************/
uint32_t testCaseNumber;

/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief Application-specific implementation of the SystemInitHook() weak function.
 */
void SystemInitHook(void)
{
    /* The TrustZone should be configured as early as possible after RESET.
     * Therefore it is called from SystemInit() during startup. The SystemInitHook() weak function
     * overloading is used for this purpose.
     */
    BOARD_InitTrustZone();
}

/*!
 * @brief HardFault handler. This handler can called from both normal and secure world
 */
void HardFault_Handler(void)
{
    uint32_t ahb_violation_status;
    uint32_t i;
    ahb_secure_fault_info_t ahb_violation_info;

    /* Handling SAU related secure faults */
    PRINTF("\r\nEntering HardFault interrupt!\r\n");
    if (SAU->SFSR != 0)
    {
        if (SAU->SFSR & SAU_SFSR_INVEP_Msk)
        {
            /* Invalid Secure state entry point */
            PRINTF("SAU->SFSR:INVEP fault: Invalid entry point to secure world.\r\n");
        }
        else if (SAU->SFSR & SAU_SFSR_AUVIOL_Msk)
        {
            /* AUVIOL: SAU violation  */
            PRINTF("SAU->SFSR:AUVIOL fault: SAU violation. Access to secure memory from normal world.\r\n");
        }
        else if (SAU->SFSR & SAU_SFSR_INVTRAN_Msk)
        {
            /* INVTRAN: Invalid transition from secure to normal world  */
            PRINTF("SAU->SFSR:INVTRAN fault: Invalid transition from secure to normal world.\r\n");
        }
        else
        {
            PRINTF("Another SAU error.\r\n");
        }
        if (SAU->SFSR & SAU_SFSR_SFARVALID_Msk)
        {
            /* SFARVALID: SFAR contain valid address that caused secure violation */
            PRINTF("Address that caused SAU violation is 0x%X.\r\n", SAU->SFAR);
        }
    }

    /* Handling secure bus related faults */
    if (SCB->CFSR != 0)
    {
        if (SCB->CFSR & SCB_CFSR_IBUSERR_Msk)
        {
            /* IBUSERR: Instruction bus error on an instruction prefetch */
            PRINTF("SCB->BFSR:IBUSERR fault: Instruction bus error on an instruction prefetch.\r\n");
        }
        else if (SCB->CFSR & SCB_CFSR_PRECISERR_Msk)
        {
            /* PRECISERR: Instruction bus error on an instruction prefetch */
            PRINTF("SCB->BFSR:PRECISERR fault: Precise data access error.\r\n");
        }
        else
        {
            PRINTF("Another secure bus error.\r\n");
        }
        if (SCB->CFSR & SCB_CFSR_BFARVALID_Msk)
        {
            /* BFARVALID: BFAR contain valid address that caused secure violation */
            PRINTF("Address that caused secure bus violation is 0x%X.\r\n", SCB->BFAR);
        }
    }

    /* Handling non-secure bus related faults */
    if (SCB_NS->CFSR != 0)
    {
        if (SCB_NS->CFSR & SCB_CFSR_IBUSERR_Msk)
        {
            /* IBUSERR: Instruction bus error on an instruction prefetch */
            PRINTF("SCB_NS->BFSR:IBUSERR fault: Instruction bus error on an instruction prefetch.\r\n");
        }
        else if (SCB_NS->CFSR & SCB_CFSR_PRECISERR_Msk)
        {
            /* PRECISERR: Data bus error on an data read/write */
            PRINTF("SCB_NS->BFSR:PRECISERR fault: Precise data access error.\r\n");
        }
        else
        {
            PRINTF("Another secure bus error.\r\n");
        }
        if (SCB_NS->CFSR & SCB_CFSR_BFARVALID_Msk)
        {
            /* BFARVALID: BFAR contain valid address that caused secure violation */
            PRINTF("Address that caused secure bus violation is 0x%X.\r\n", SCB_NS->BFAR);
        }
    }

    /* Handling AHB secure controller related faults.
     * AHB secure controller faults raise secure bus fault. Detail fault info
     * can be read from AHB secure controller violation registers */
    ahb_violation_status = AHB_SECURE_CTRL->SEC_VIO_INFO_VALID;
    if (ahb_violation_status != 0)
    {
        PRINTF("\r\nAdditional AHB secure controller error information:\r\n");
        for (i = 0; i < (AHB_LAYERS_COUNT - 1); i++)
        {
            if (ahb_violation_status & 0x1U)
            {
                ahb_violation_info.value = AHB_SECURE_CTRL->SEC_VIO_MISC_INFO[i];
                PRINTF("Secure error at AHB layer %d.\r\n", i);
                PRINTF("Address that caused secure violation is 0x%X.\r\n", AHB_SECURE_CTRL->SEC_VIO_ADDR[i]);
                PRINTF("Secure error caused by bus master number %d.\r\n", ahb_violation_info.fault_info.master_number);
                PRINTF("Security level of master %d.\r\n", ahb_violation_info.fault_info.master_sec_level);
                PRINTF("Secure error happened during ");
                switch (ahb_violation_info.fault_info.access_type)
                {
                    case 0:
                        PRINTF("read code access.\r\n");
                        break;
                    case 2:
                        PRINTF("read data access.\r\n");
                        break;
                    case 3:
                        PRINTF("read code access.\r\n");
                        break;
                    default:
                        PRINTF("unknown access.\r\n");
                        break;
                }
            }
            ahb_violation_status = ahb_violation_status >> 1;
        }
    }
    /* Perform system RESET */
    SCB->AIRCR =
        (SCB->AIRCR & ~SCB_AIRCR_VECTKEY_Msk) | (0x05FAUL << SCB_AIRCR_VECTKEY_Pos) | SCB_AIRCR_SYSRESETREQ_Msk;
}


/*!
 * @brief Main function
 */
int main(void)
{
    funcptr_ns ResetHandler_ns;
    /* Init board hardware. */
    /* set BOD VBAT level to 1.65V */
    POWER_SetBodVbatLevel(kPOWER_BodVbatLevel1650mv, kPOWER_BodHystLevel50mv, false);
    /* attach main clock divide to FLEXCOMM0 (debug console) */
    CLOCK_AttachClk(BOARD_DEBUG_UART_CLK_ATTACH);

    BOARD_InitPins();
    //BOARD_BootClockPLL150M();
    BOARD_BootClockFROHF96M();
    BOARD_InitDebugConsole();
    PRINTF("Hello from secure world!\r\n");

    /* Set non-secure main stack (MSP_NS) */
    __TZ_set_MSP_NS(*((uint32_t *)(NON_SECURE_START)));

    /* Set non-secure vector table */
    SCB_NS->VTOR = NON_SECURE_START;

    /* Get non-secure reset handler */
    ResetHandler_ns = (funcptr_ns)(*((uint32_t *)((NON_SECURE_START) + 4U)));

    /* Call non-secure application */
    PRINTF("Entering normal world.\r\n");

    ResetHandler_ns();
    while (1)
    {
        /* This point should never be reached */
    }
}
