/* <@LICENSE>
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at:
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * </@LICENSE>
 */
/**
 * @file:     cb_mgmt.h
 * @author:   Titouan Mesot
 * @date:     Jun 26, 2015
 * @Version:  0.3
 * @brief : The part of crypt_bridge provide the mgmt interface
 */

#pragma once
#ifndef CB_MGMT_H
#define CB_MGMT_H

#include <zmq.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <sodium.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <syslog.h>


/*declaration of type of parameters (params_type) in cb_params  */

#define cb_params_key_seq       0  /**< payload is a seqNum */
#define cb_params_cmd           1  /**< payload is iptables rules*/
#define cb_params_fmw           2  /**< payload is a newfirmware */


/*declaration of type of payload*/

#define cb_pl_trust_init         0  /**< payload is cb_init_trust */
#define cb_pl_trust_ok           1  /**< payload is cb_trust_ok */
#define cb_pl_trust_wait         2  /**< payload is cb_trust_wait */
#define cb_pl_hb                 3  /**< payload is cb_heartbeat */
#define cb_pl_hb_ok              4  /**< payload is cb_heartbeat_ok */
#define cb_pl_get_params         5  /**< payload is cb_get_params */
#define cb_pl_params             6  /**< payload is cb_params */

/*declaration of size*/

#define CB_KEY_READABLE 41

/*shared variables*/

extern unsigned char key[crypto_secretbox_KEYBYTES];
extern unsigned char old_key[crypto_secretbox_KEYBYTES];

extern int seq_num;
extern int old_seq_num;

extern pthread_mutex_t mutex_key;
extern pthread_mutex_t mutex_seq_num;


/* Container struct */
 typedef struct  __attribute__((__packed__)) {
    uint8_t version; 
    uint8_t payload_type;
    uint16_t payload_size; 
} cb_frame;


/* trust init frame struct */
typedef struct  __attribute__((__packed__)) {
    uint32_t id;
    char pub_key[CB_KEY_READABLE];
} cb_trust_init ; 

/* trust ok frame struct */
//No struct, is empty only frame + type of payload

/* trust wait frame struct */
//No struct, is empty only frame + type of payload


/* control hb_params frame struct */
typedef struct  __attribute__((__packed__)) {
    uint16_t params_length;
    uint16_t params_type;
    uint32_t seq; 
} cb_params ; 



/* 
 * Management thread
 */
extern void* cb_mgmt (void* void_ptr); 

#endif

