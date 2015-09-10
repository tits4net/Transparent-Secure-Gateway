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
 * @file:     cb_mgmt.c
 * @author:   Titouan Mesot
 * @date:     Jul, 04 2015
 * @Version:  0.4
 */

#include "cb_mgmt.h"

/* shared variables */

unsigned char key[crypto_secretbox_KEYBYTES];
unsigned char old_key[crypto_secretbox_KEYBYTES];

int seq_num;
int old_seq_num; 
pthread_mutex_t mutex_key;
pthread_mutex_t mutex_seq_num;

/* Key read / write methods and configuration file read / write*/

int get_server_pub_key(char *pub_key){
    char*buff = malloc(100); 
    int res = -1; 
    FILE *fp;
    fp=fopen("/etc/crypt_bridge/cb.conf", "r");
    if(fp == NULL){
        syslog (LOG_ERR, "Error: %d (%s)\n", errno, strerror(errno));
        exit(EXIT_FAILURE); 
    }
    fgets(buff, 100, fp); 
    fgets(buff, 100, fp); 
    res = fscanf(fp, "server_pub=%s", pub_key);
    fclose(fp); 
    free(buff); 
    return res; 
}

int get_server_ip(char *server_ip){
    int res = -1; 
    FILE *fp;
    fp=fopen("/etc/crypt_bridge/cb.conf", "r");
    if(fp == NULL){
        syslog (LOG_ERR, "Error: %d (%s)\n", errno, strerror(errno));
        exit(EXIT_FAILURE); 
    }
    res = fscanf(fp, "server_ip=%s", server_ip);
    fclose(fp); 
    return res; 
}

int get_node_id(){
    char*buff = malloc(100); 
    int id = 0; 
    FILE *fp;
    fp=fopen("/etc/crypt_bridge/cb.conf", "r"); 
    fgets(buff, 100, fp); 
    fscanf(fp, "node_name=%i", &id);
    fclose(fp); 
    free(buff); 
    return id; 
}

int get_client_pub_key(char *my_pub_key){
    char*buff = malloc(100); 
    int res = -1; 
    FILE *fp;
    fp=fopen("/etc/crypt_bridge/cb.conf", "r");
    if(fp == NULL){
        syslog (LOG_ERR, "Error: %d (%s)\n", errno, strerror(errno));
        exit(EXIT_FAILURE); 
    }
    fgets(buff, 100, fp); 
    fgets(buff, 100, fp); 
    fgets(buff, 100, fp); 
    res = fscanf(fp, "client_pub=%s", my_pub_key);
    fclose(fp); 
    free(buff); 
    return res; 
}

int get_client_secret_key(char *my_secret_key){
    char*buff = malloc(200); 
    int res = -1; 
    FILE *fp;
    fp=fopen("/etc/crypt_bridge/cb.conf", "r");
    if(fp == NULL){
        syslog (LOG_ERR, "Error: %d (%s)\n", errno, strerror(errno));
        exit(EXIT_FAILURE); 
    }
    fgets(buff, 100, fp); 
    fgets(buff, 100, fp); 
    fgets(buff, 100, fp); 
    fgets(buff, 100, fp); 
    res = fscanf(fp, "client_secret=%s", my_secret_key);
    fclose(fp); 
    free(buff); 
    return res; 
}

/* Management thread */

void* cb_mgmt (void* void_ptr)
{
    char *buffer = malloc(1500);
    char *buffer_rcv = malloc(1500);
    char *my_pub_key = malloc(CB_KEY_READABLE);
    char *my_secret_key = malloc(CB_KEY_READABLE);
    char *server_public = malloc(CB_KEY_READABLE);
    char *server_ip_full = malloc(48);
    char *server_ip = malloc(48);
    
    get_client_secret_key(my_secret_key); 
    get_client_pub_key(my_pub_key); 
    get_server_pub_key(server_public);
    get_server_ip(server_ip);
    sprintf(server_ip_full, "tcp://%s:5555", server_ip); 
    syslog (LOG_NOTICE , "Connecting to trusting server (%s)\n", server_ip_full);
    
    void *context = zmq_ctx_new ();
    void *requester = zmq_socket (context, ZMQ_REQ);
    int rc = zmq_setsockopt (requester, ZMQ_CURVE_SERVERKEY, server_public, CB_KEY_READABLE-1);
    rc = zmq_setsockopt (requester, ZMQ_CURVE_PUBLICKEY, my_pub_key, CB_KEY_READABLE-1);
    rc = zmq_setsockopt (requester, ZMQ_CURVE_SECRETKEY, my_secret_key, CB_KEY_READABLE-1);
    assert(rc == 0); 
    zmq_connect (requester, server_ip_full);
    
    //Create init trust frame
    cb_frame *hello_frm = malloc(sizeof(cb_frame));
    cb_trust_init *hello_trust_init = malloc(sizeof(cb_trust_init));
    hello_frm->version = 1; 
    hello_frm->payload_type = cb_pl_trust_init; 
    hello_frm->payload_size = htons(sizeof(cb_trust_init));
    int id = get_node_id(); 
    hello_trust_init->id = htonl(id);
    memcpy(hello_trust_init->pub_key,my_pub_key, CB_KEY_READABLE);
    memcpy(buffer, hello_frm, sizeof(cb_frame)); 
    memcpy(&buffer[sizeof(cb_frame)],hello_trust_init, sizeof(cb_trust_init)); 
    free (hello_frm); 
    free (hello_trust_init); 
    
    //Send init_trust
    syslog (LOG_INFO , "Sending Hello …\n");
    zmq_send (requester, buffer, sizeof(cb_frame)+sizeof(cb_trust_init)-1, 0); // -1 to avoid null byte of string
    syslog (LOG_INFO , "Hello Sended …Waiting respons\n");
    zmq_recv (requester, buffer_rcv, sizeof(cb_frame), 0);
    syslog (LOG_INFO , "Received response\n"); 
    
    //cast get message if OK we connect to second socket else we send init every 5 seconds. 
    cb_frame *hello_rcv = (cb_frame*)buffer_rcv;
    //wait until accept 
    while(hello_rcv->payload_type == cb_pl_trust_wait){
        int res = 0; 
        hello_frm = malloc(sizeof(cb_frame));
        hello_trust_init = malloc(sizeof(cb_trust_init));
        hello_frm->version = 1; 
        hello_frm->payload_type = cb_pl_trust_init; 
        hello_frm->payload_size = htons(sizeof(cb_trust_init));
        int id = get_node_id(); 
        hello_trust_init->id = htonl(id);
        memcpy(hello_trust_init->pub_key,my_pub_key, CB_KEY_READABLE);
        memcpy(buffer, hello_frm, sizeof(cb_frame)); 
        memcpy(&buffer[sizeof(cb_frame)],hello_trust_init, sizeof(cb_trust_init)); 
        free (hello_frm); 
        free (hello_trust_init); 
        //Send init_trust
        syslog (LOG_INFO , "Sending Hello …\n");
        res = zmq_send (requester, buffer, sizeof(cb_frame)+sizeof(cb_trust_init)-1, 0); // -1 to avoid null byte of string

        if(res == -1)
            syslog (LOG_ERR, "Error: %d (%s)\n", errno, zmq_strerror (errno));

        syslog (LOG_INFO , "Hello Sended …Waiting respons\n");
        res = zmq_recv (requester, buffer_rcv, sizeof(cb_frame), 0);
        hello_rcv = (cb_frame*)buffer_rcv;
        
        if(res == -1)
            syslog (LOG_ERR, "Error: %d (%s)\n", errno, zmq_strerror(errno));
    
        syslog (LOG_INFO , "Received response\n"); 
        sleep(1);
    }
    //we close the unsec socket and start the new one
    zmq_close (requester);
    zmq_ctx_destroy (context);
    free(buffer_rcv);
    sleep(2); //wait until server UP
    syslog (LOG_NOTICE , "Connecting to trusted server…\n");
    context = zmq_ctx_new ();
    requester = zmq_socket (context, ZMQ_SUB);
    rc = zmq_setsockopt (requester, ZMQ_CURVE_SERVERKEY, server_public, CB_KEY_READABLE-1);
    rc = zmq_setsockopt (requester, ZMQ_CURVE_PUBLICKEY, my_pub_key, CB_KEY_READABLE-1);
    rc = zmq_setsockopt (requester, ZMQ_CURVE_SECRETKEY, my_secret_key, CB_KEY_READABLE-1);
    rc = zmq_setsockopt (requester, ZMQ_SUBSCRIBE, NULL, 0);
    get_server_ip(server_ip);
    sprintf(server_ip_full, "tcp://%s:5556", server_ip); 
    rc = zmq_connect(requester, server_ip_full);
    while(1){
        zmq_recv (requester, buffer,sizeof(cb_frame)+sizeof(cb_params)+1500, 0);
        cb_params *params_rcv_payload = (cb_params*)&buffer[sizeof(cb_frame)];
        char* param = malloc(ntohs(params_rcv_payload->params_length));
        param[ntohs(params_rcv_payload->params_length)] = '\0'; //adding missing null from python
        memcpy(param,&buffer[sizeof(cb_frame)+sizeof(cb_params)], ntohs(params_rcv_payload->params_length));
        syslog (LOG_DEBUG , "param type is %i\n", ntohs(params_rcv_payload->params_type)); 
        syslog (LOG_DEBUG , "param is %s\n", param);    
        if(ntohs(params_rcv_payload->params_type) == cb_params_cmd){
            syslog (LOG_DEBUG , "Command call is : %s", param); 
            system(param);    
        }
        else if(ntohs(params_rcv_payload->params_type) == cb_params_key_seq){
            syslog (LOG_DEBUG , "We rcv the key : %s with seq %d", param, params_rcv_payload->seq); 
            pthread_mutex_lock(&mutex_key);
            if(memcmp(&key, param, crypto_secretbox_KEYBYTES) != 0){
                memcpy(old_key, key, crypto_secretbox_KEYBYTES); 
                memcpy(key, param, crypto_secretbox_KEYBYTES);
            }
            pthread_mutex_unlock(&mutex_key);
            pthread_mutex_lock(&mutex_seq_num);
            old_seq_num = seq_num; 
            seq_num = params_rcv_payload->seq; 
            pthread_mutex_unlock(&mutex_seq_num);
        }
        free(param);
    }
    free(buffer);
    free(buffer_rcv); 
    free(my_pub_key);
    free(my_secret_key);
    free(server_public);
    free(server_ip_full);
    free(server_ip);
    return 0;
}
