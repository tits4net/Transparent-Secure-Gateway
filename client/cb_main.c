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
 * @file:     cb_main.c
 * @author:   Titouan Mesot
 * @date:     Jul, 04 2015
 * @Version:  0.4
 * @brief: Main composant of crypt_bridge
 * 
 * It start the management thread and hook the netfilter-queue 
 * callback. 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sodium.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <pthread.h>
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "cb_net_utils.h"
#include "cb_mgmt.h"


#define IP_PROTO_CIPH 253

static int signal_catched = 0; 


static void catch_signal (int signal)
{
    syslog (LOG_ERR, "signal=%d catched\n", signal);
    signal_catched++;
    closelog();
    exit(0);
}

static void fork_process()
{
    pid_t pid = fork();
    switch (pid) {
    case  0: break; // child process has been created
    case -1: syslog (LOG_ERR, "ERROR while forking"); exit (1); break;  
    default: exit(0);  // exit parent process with success
    }
}


void daemonize(){
        
    //Create processus child and terminate parent
    fork_process();
    
    //Change session ID
    if (setsid() == -1) {
        syslog (LOG_ERR, "ERROR while creating new session"); 
        exit (1);
    }
    
    //Create processus deamon and terminate parent
    fork_process();
    
    //Capture all required signals
    struct sigaction act = {.sa_handler = catch_signal,};
    sigaction (SIGHUP,  &act, NULL);  //  1 - hangup
    sigaction (SIGINT,  &act, NULL);  //  2 - terminal interrupt
    sigaction (SIGQUIT, &act, NULL);  //  3 - terminal quit
    sigaction (SIGABRT, &act, NULL);  //  6 - abort
    sigaction (SIGTERM, &act, NULL);  // 15 - termination
    sigaction (SIGTSTP, &act, NULL);  // 19 - terminal stop signal
    //sigaction (SIGCHLD, &act, NULL);  // 19 - terminal stop signal - to avoid system() crash
        signal(SIGCHLD, SIG_IGN);
    //Update file mode creation mask
    umask(0027);

    //Change working directory to appropriate place
    if (chdir ("/tmp") == -1) {
        syslog (LOG_ERR, "ERROR while changing to working directory"); 
        exit (1);
    }
    //Close all open file descriptors (STDIN(0), STDOUT(1), STDERR(2) too)
    int fd; 
    for (fd = sysconf(_SC_OPEN_MAX); fd >= 0; fd--) {
        close (fd);
    }

    //Redirect stdin, stdout and stderr to /dev/null
    if (open ("/dev/null", O_RDWR) != STDIN_FILENO) {
        syslog (LOG_ERR, "ERROR while opening '/dev/null' for stdin");
        exit (1);
    }
    if (dup2 (STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO) {
        syslog (LOG_ERR, "ERROR while opening '/dev/null' for stdout");
        exit (1);
    }
    if (dup2 (STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO) {
        syslog (LOG_ERR, "ERROR while opening '/dev/null' for stderr");
        exit (1);
    }
    
    //Option: open syslog for message logging
    //  open immediately the connection and for each message add the pid
    openlog (NULL, LOG_NDELAY | LOG_PID, LOG_DAEMON); 
    syslog (LOG_NOTICE, "Crypt_bridge has started...");


}

/* NFQueue call back */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data){      
                  
    if (sodium_init() == -1) {
        syslog (LOG_ERR, "Libsodium Init fail");
        exit(1);
    }
        
    //Get packetId
    //Tempory value is used to store
    //should be avoid but doesn't work in MIPS target without
    //thoses lines 
    u_int32_t id_mips = 0;
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id_mips = ntohl(ph->packet_id);
    }
    id = id_mips; 
        
        
    unsigned char *original_payload;
    int original_payload_size;
    int final_size; 
    int result = NF_DROP; //we drop the packet if somethings goes wrong
    original_payload_size = nfq_get_payload(nfa, &original_payload);
    // The IP header 
    struct ip_header *ip;  
    //get the ip header           
    ip = (struct ip_header*)(original_payload);
    //compute header lenght
    int size_ip = IP_HL(ip)*4;
    //check if is one of our encrypted packet
    if(ip->ip_p == IP_PROTO_CIPH){
    //we have to decrypt
    //prepare the final payload 
        unsigned char final_payload[original_payload_size   -sizeof(struct cb_gen_header)
                                                            -sizeof(struct cb_type1_header)
                                                            -crypto_secretbox_MACBYTES];
                                                                                
        int final_payload_size = original_payload_size  -sizeof(struct cb_gen_header) 
                                                        -sizeof(struct cb_type1_header) 
                                                        -crypto_secretbox_MACBYTES;  
                                                                        
        //prepare store for payload over ip 
        unsigned char payload_over_ip[original_payload_size-size_ip]; 
        int payload_over_ip_size = original_payload_size - size_ip; 
        // Get all the payload over IP
        memcpy(payload_over_ip, &original_payload[size_ip], payload_over_ip_size);
        struct cb_gen_header *gen_h = (struct cb_gen_header*)payload_over_ip; 
        unsigned char nonce[crypto_secretbox_NONCEBYTES]; 
        memcpy(nonce, gen_h->nonce, crypto_secretbox_NONCEBYTES);       
        unsigned char decrypted[ntohs(gen_h->payload_len)-crypto_secretbox_MACBYTES];
        pthread_mutex_lock(&mutex_key);
        //Try to decrypt with current key
        int dec_res = -1; 
        dec_res = crypto_secretbox_open_easy(decrypted, &payload_over_ip[sizeof(struct cb_gen_header)], ntohs(gen_h->payload_len), nonce, key); 
        if (dec_res != 0) {
                syslog (LOG_ERR, "decryption Error with current key"); 
                dec_res = crypto_secretbox_open_easy(decrypted, &payload_over_ip[sizeof(struct cb_gen_header)], ntohs(gen_h->payload_len), nonce, old_key);
                if(dec_res != 0){
                        pthread_mutex_unlock(&mutex_key);
                        syslog (LOG_ERR, "decryption Error with old key too"); 
                        result = NF_DROP; 
                        return nfq_set_verdict(qh, id, result, 0, NULL);     
                }
        }
        pthread_mutex_unlock(&mutex_key);
        //get payloadtype 
        unsigned char payload_type = decrypted[0]; //get first byte for type
        if (payload_type == 1){
                struct cb_type1_header *typ1_h = (struct cb_type1_header*)decrypted;
                //check seqNum
                pthread_mutex_lock(&mutex_seq_num);
                if(typ1_h->seqnum != seq_num){
                        syslog (LOG_ERR, "Seq Num mismatch - check with old one"); 
                        if(typ1_h->seqnum != old_seq_num){
                                pthread_mutex_unlock(&mutex_seq_num);
                                syslog (LOG_ERR, "Seq Num mismatch - packet denied"); 
                                result = NF_DROP; 
                                return nfq_set_verdict(qh, id, result, 0, NULL);
                        }
                }
                pthread_mutex_unlock(&mutex_seq_num);
                //put original data in final payload
                memcpy(&final_payload[size_ip],&decrypted[sizeof(struct cb_type1_header)], final_payload_size);
                memcpy(final_payload, ip, size_ip); 
                //set original proto / flag
                struct ip_header *ip_new;  
                ip_new = (struct ip_header*)(final_payload);
                ip_new->ip_p = typ1_h->ip_proto; 
                //recompute total length (in byte)
                ip_new->ip_len = htons(final_payload_size);
                //recompute checksum in C , in linux it's done in ASM, we do it in C for portability
                ip_new->ip_sum = 0; 
                //compute new one
                ip_new->ip_sum = ip_checksum(final_payload, size_ip);
                //printf("Decrypted packet send back\n"); 
                result = NF_ACCEPT; 
                final_size = final_payload_size; 
        }
        return nfq_set_verdict(qh, id, result, final_size, final_payload);
    }
    else{
    //we encrypt
    //prepare the final payload 
        unsigned char final_payload[original_payload_size+sizeof(struct cb_gen_header)
                                                         +sizeof(struct cb_type1_header)
                                                         +crypto_secretbox_MACBYTES];
                                                                                
        unsigned char payload_over_ip[(original_payload_size-size_ip)+sizeof(struct cb_type1_header)]; 
        int payload_over_ip_size = (original_payload_size - size_ip)+sizeof(struct cb_type1_header); 
        // Get all the payload over IP
        memcpy(&payload_over_ip[sizeof(struct cb_type1_header)], &original_payload[size_ip], payload_over_ip_size-sizeof(struct cb_type1_header));
        //put encrypted header 
        struct cb_type1_header *typ1_h = (struct cb_type1_header*)payload_over_ip; 
        typ1_h->payload_type = 1;       
        typ1_h->ip_proto = ip->ip_p; 
        pthread_mutex_lock(&mutex_seq_num);
        typ1_h->seqnum = seq_num; 
        pthread_mutex_unlock(&mutex_seq_num);
        //encrypt payload
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(nonce, sizeof(nonce));
        unsigned char ciphertext[crypto_secretbox_MACBYTES + payload_over_ip_size];
        pthread_mutex_lock(&mutex_key);
        crypto_secretbox_easy(ciphertext, payload_over_ip, (payload_over_ip_size), nonce, key);
        pthread_mutex_unlock(&mutex_key);
        int payload_over_ip_size_enc = payload_over_ip_size + crypto_secretbox_MACBYTES; 
        //crate meta data header
        struct cb_gen_header *gen_h = (struct cb_gen_header*)&final_payload[size_ip]; 
        //fill it
        gen_h->version = 1; 
        memcpy(gen_h->nonce,nonce,sizeof(nonce));
        gen_h->payload_len = htons(payload_over_ip_size_enc); 
        //put payload in old packet
        memcpy(&final_payload[size_ip+sizeof(struct cb_gen_header)],ciphertext, payload_over_ip_size_enc);
        //recompute total length (in byte)
        ip->ip_len = htons(size_ip+payload_over_ip_size_enc + sizeof(struct cb_gen_header));
        //Change protocole type to experimental (http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
        ip->ip_p = IP_PROTO_CIPH; 
        //recompute checksum in C , in linux it's done in ASM, we do it in C for portability
        //but first remove old one
        ip->ip_sum = 0; 
        //compute new one
        ip->ip_sum = ip_checksum(ip, size_ip);
        //put ip header in the final paquet
        memcpy(final_payload, ip, size_ip); 
        final_size = size_ip + payload_over_ip_size_enc + sizeof(struct cb_gen_header); 
        result = NF_ACCEPT; 
        return nfq_set_verdict(qh, id, result, final_size, final_payload);
    }
    return nfq_set_verdict(qh, id, result, 0, NULL);
}

int main(int argc, char **argv)
{
    if (pthread_mutex_init(&mutex_key, NULL) != 0)
    {
        syslog (LOG_ERR, "\n mutex init failed\n");
        return 1;
    }
    daemonize(); 
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    uint32_t queue = 0;
    char buf[4096] __attribute__ ((aligned));
    //Starting mgmt thread
    pthread_t t_mgmt; 
    pthread_create(&t_mgmt,NULL,&cb_mgmt, NULL);
    syslog (LOG_DEBUG, "opening library handle\n");
    h = nfq_open();
    if (!h) {
        syslog (LOG_ERR, "error during nfq_open()\n");
        exit(1);
    }
    syslog (LOG_DEBUG, "unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        syslog (LOG_DEBUG,"error during nfq_unbind_pf()\n");
        exit(1);
    }
    syslog (LOG_DEBUG, "binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        syslog (LOG_DEBUG,"error during nfq_bind_pf()\n");
        exit(1);
    }
    syslog (LOG_DEBUG, "binding this socket to queue '%d'\n", queue);
    qh = nfq_create_queue(h, queue, &cb, NULL);
    if (!qh) {
        syslog (LOG_DEBUG,"error during nfq_create_queue()\n");
        exit(1);
    }

    syslog (LOG_DEBUG, "setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        syslog (LOG_DEBUG, "can't set packet_copy mode\n");
        exit(1);
    }
    syslog (LOG_DEBUG, "Waiting for packets...\n");
    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            syslog(LOG_ERR,"losing packets!\n");
            continue;
        }
        syslog (LOG_ERR, "recv failed");
        break;
    }

    syslog (LOG_DEBUG,"unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    syslog (LOG_DEBUG,"closing library handle\n");
    nfq_close(h);
    closelog();
    exit(0);
}
