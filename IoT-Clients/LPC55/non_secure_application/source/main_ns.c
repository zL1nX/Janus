/*
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_device_registers.h"
#include "board.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "fsl_power.h"
#include "network_communication.h"
#include "janus_communication_ns.h"
#include <time.h>


#include "clock_config.h"


#include "platform/iot_network_freertos.h"


/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define DEMO_SEC_ADDRESS    0x10000000
#define DEMO_NONSEC_ADDRESS 0x20130000
typedef void (*funcptr_t)(char const *s);

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

/* DWT (Data Watchpoint and Trace) registers, only exists on ARM Cortex with a DWT unit */
#define KIN1_DWT_CONTROL             (*((volatile uint32_t*)0xE0001000))
/*!< DWT Control register */
#define KIN1_DWT_CYCCNTENA_BIT       (1UL<<0)
/*!< CYCCNTENA bit in DWT_CONTROL register */
#define KIN1_DWT_CYCCNT              (*((volatile uint32_t*)0xE0001004))
/*!< DWT Cycle Counter register */
#define KIN1_DEMCR                   (*((volatile uint32_t*)0xE000EDFC))
/*!< DEMCR: Debug Exception and Monitor Control Register */
#define KIN1_TRCENA_BIT              (1UL<<24)


#define KIN1_InitCycleCounter() \
  KIN1_DEMCR |= KIN1_TRCENA_BIT
  /*!< TRCENA: Enable trace and debug block DEMCR (Debug Exception and Monitor Control Register */
 
#define KIN1_ResetCycleCounter() \
  KIN1_DWT_CYCCNT = 0
  /*!< Reset cycle counter */
 
#define KIN1_EnableCycleCounter() \
  KIN1_DWT_CONTROL |= KIN1_DWT_CYCCNTENA_BIT
  /*!< Enable cycle counter */
 
#define KIN1_DisableCycleCounter() \
  KIN1_DWT_CONTROL &= ~KIN1_DWT_CYCCNTENA_BIT
  /*!< Disable cycle counter */
 
#define KIN1_GetCycleCounter() \
  KIN1_DWT_CYCCNT
  /*!< Read cycle counter register */
    /*!< Trace enable bit in DEMCR register */
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


void janus_offchain_communication()
{
    init_session_ns();

    // retrieve data from chain

	//int sock = socket_init("10.168.1.180", 18083);
    int sock = 2345;

    // retrieve data from chain(): httpget and cjson deconstruct

    // SGX那端对应着round_one_recv
    janus_round_one_send(sock);

    janus_round_two_recv(sock);

    //janus_round_three_send(sock);

    qcom_socket_close(sock);
}

void janus_chain_communication(void)
{
//	uint8_t* raw_json = NULL;
//	size_t json_len = 0;
//	const char* url_body = "/state/d8237565e86d7a1a709f3e40b4ff9f42e0f35c6b7da6a68ff70b004db1cfd66795d5b2";
//	raw_json = http_get_from_chain(&json_len, "10.168.1.180", url_body, 8008, 5000);
//	configPRINTF(("%d %s\r\n", json_len, raw_json));
//
//	uint8_t data_in_json[128];
//	size_t data_len = 0;
//	parse_json_from_chain(data_in_json, &data_len, raw_json);
//	configPRINTF(("%d %x \r\n", data_len, data_in_json[0]));
//
//	if(raw_json != NULL)
//	{
//		custom_free(raw_json);
//	}
	janus_contract_client();

}

void main_task(void *pvParameters)
{
    if (SYSTEM_Init() != pdPASS)
    {
        configPRINTF(("SYSTEM_Init Wrong\r\n"));
        vTaskDelete(NULL);
    }
    init_session_ns();

    int data_size = 0;
    uint8_t out[2000];
    char* aid_list[3] = {"12341", "12342", "12343"};

    uint32_t a = 0, b = 0; /* number of cycles */

    KIN1_InitCycleCounter(); /* enable DWT hardware */
    KIN1_ResetCycleCounter(); /* reset cycle counter */
    KIN1_EnableCycleCounter(); /* start counting */

    // test for submit_device_condition_ns
    for(int i = 0; i < 3; i++)
    {   
        a = KIN1_GetCycleCounter(); /* get cycle counter */
        data_size = submit_audit_request_ns(out, "deadbeaf", "1234", "5678");
        b = KIN1_GetCycleCounter(); /* get cycle counter */
        configPRINTF(("Time: %d cycles\r\n", b - a));
    }
    KIN1_DisableCycleCounter(); /* disable counting if not used any more */

    // data_size = submit_device_condition_ns(out, ONLY_OFF_CHAIN);
    // data_size = submit_attestation_state_ns(out, "1234", ONLY_OFF_CHAIN);
    // data_size = submit_attestation_challenge_ns(out, "1234");
    // data_size = submit_attestation_response_ns(out);
    // data_size = submit_verification_request_ns(out, aid_list);
    //data_size = submit_audit_credential_ns(out, "1234", "1234", false);
    // data_size = submit_audit_request_ns(out, "deadbeaf", "1234", "5678");
    //uint32_t end = SysTick->VAL;

    configPRINTF(("data_size: %d\r\n", data_size));


    //janus_offchain_communication();
    //janus_chain_communication();
    // if (initNetwork() != 0)
    // {
    //     configPRINTF(("Network init failed, stopping task.\r\n"));
    //     vTaskDelete(NULL);
    // }
    // else
    // {
    // janus_chain_communication();
    // //socket_test("10.168.1.180", 18083);
    //     //janus_offchain_communication();
    // }

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
       // char output3[1000];
// trustQuerry("test","tets",0.7, &output, 1000);
       // checkRequest(&output2,1000);


        //submitEvidenceVeneer("testID","proverID",&output3,1000);



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
