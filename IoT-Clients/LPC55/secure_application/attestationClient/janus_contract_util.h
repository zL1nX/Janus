/*
 * janus_contract_util.h
 *
 *  Created on: 2023年5月23日
 *      Author: LoCCS-GoCE
 */

#ifndef JANUS_CONTRACT_UTIL_H_
#define JANUS_CONTRACT_UTIL_H_

#include "janus_util.h"
#include "cbor.h"
#include "utils.h"
#include "batch.pb-c.h"
#include "sha256.h"
#include "sha512.h"
//#include "secp256k1.h"
//#include "secp256k1_preallocated.h"
//

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

#define DEVICE_FREQUENCY 150000000

uint8_t * _wrap_and_send(char* name, char *action, int size, uint8_t *data, int n_input, char *input_address_list[], int n_output, char *output_address_list[]);
//char* calculate_address(uint8_t* content);
char* assembleAddress(const char *name, uint8_t* data, size_t size);
uint8_t * my_wrap_and_send(char* name, char *action, int size, uint8_t *data, int* data_size, int n_input, char *input_address_list[], int n_output, char *output_address_list[]);



#endif /* JANUS_CONTRACT_UTIL_H_ */
