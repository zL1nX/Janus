/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "board.h"
#include "veneer_table.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "fsl_power.h"
#include "network_communication.h"
#include "janus_communication_ns.h"



#include "clock_config.h"


#include "platform/iot_network_freertos.h"


/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define DEMO_SEC_ADDRESS    0x10000000
#define DEMO_NONSEC_ADDRESS 0x20130000
typedef void (*funcptr_t)(char const *s);
#define PRINTF_NSE DbgConsole_Printf_NSE

#define LOGGING_TASK_PRIORITY   (tskIDLE_PRIORITY + 1)
#define LOGGING_TASK_STACK_SIZE (200)
#define LOGGING_QUEUE_LENGTH    (16)
#define TIMEOUT pdMS_TO_TICKS(30000UL)
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

void SystemInit(void)
{
}



void print_string(const char *string)
{
    PRINTF(string);
}


void janus_communication()
{
    int sock = socket_init();

    uint8_t materials_onchain[100]; // for now

    // retrieve data from chain(): httpget and cjson deconstruct

    set_materials_onchain_e(materials_onchain);

    // SGX那端对应着round_one_recv
    janus_round_one_send(sock);

    janus_round_two_recv(sock);

    janus_round_three_send(sock);

    qcom_socket_close(sock);
}

void main_task(void *pvParameters)
{

    if (SYSTEM_Init() == pdPASS)
    {
        if (initNetwork() != 0)
        {
            configPRINTF(("Network init failed, stopping task.\r\n"));
            vTaskDelete(NULL);
        }
        else
        {
        	socket_test();
            janus_communication();
        }
    }

    vTaskDelete(NULL);
}


int main(void)
{


    /* set BOD VBAT level to 1.65V */
    POWER_SetBodVbatLevel(kPOWER_BodVbatLevel1650mv, kPOWER_BodHystLevel50mv, false);

    PRINTF_NSE("Welcome in normal world!\r\n");

    BaseType_t result = 0;
        (void)result;

        /* attach main clock divide to FLEXCOMM0 (debug console) */
        CLOCK_AttachClk(BOARD_DEBUG_UART_CLK_ATTACH);

        BOARD_InitBootPins();
        //BOARD_InitBootClocks();
        BOARD_BootClockFROHF96M();
        BOARD_InitDebugConsole();
        CRYPTO_InitHardware();
       // char output[1000];
       // char output2[1000];
       // char output3[1000];
// trustQuerry("test","tets",0.7, &output, 1000);
       // checkRequest(&output2,1000);


        //submitEvidenceVeneer("testID","proverID",&output3,1000);

   //     checkRequest(&output2,1000);

/*
        result =
            xTaskCreate(task_main, "main", TASK_MAIN_STACK_SIZE, task_main_stack, TASK_MAIN_PRIO, &task_main_task_handler);
        assert(pdPASS == result);
*/
        if (xTaskCreate(main_task, "main_task", configMINIMAL_STACK_SIZE * 8, NULL, tskIDLE_PRIORITY, NULL) != pdPASS) //prio was +1
           {
               PRINTF("Main task creation failed!.\r\n");
               while (1)
                   ;
           }

        xLoggingTaskInitialize(LOGGING_TASK_STACK_SIZE, LOGGING_TASK_PRIORITY, LOGGING_QUEUE_LENGTH);

        vTaskStartScheduler();

    while (1)
    {
    }
}

void *pvPortCalloc(size_t xNum, size_t xSize)
{
    void *pvReturn;

    pvReturn = pvPortMalloc(xNum * xSize);
    if (pvReturn != NULL)
    {
        memset(pvReturn, 0x00, xNum * xSize);
    }

    return pvReturn;
}