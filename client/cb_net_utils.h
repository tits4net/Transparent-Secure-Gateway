/*  <@LICENSE>
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
/*
 * @file:     cb_net_utils.h
 * @author:   Titouan Mesot
 * @date:     Apr 30, 2015
 * @Version:  0.3
 * @brief : This module provide the network part to the crypt_bridge application
 *
 */

#pragma once
#ifndef CB_NET_UTILS_H
#define CB_NET_UTILS_H

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/types.h>
#include <netinet/in.h>




/* Ethernet, IP and TCP header are from sniffex.c exemple in libpcap Copyright (c) 2002 Tim Carstens*/

/*  ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/*  Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct ethernet_header {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /**<  destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /**< *<  source host address */
    u_short ether_type;                     /**<  IP? ARP? RARP? etc */
};

/*  IP header */
struct ip_header {
    u_char  ip_vhl;                 /**<  version << 4 | header length >> 2 */
    u_char  ip_tos;                 /**<  type of service */
    u_short ip_len;                 /**<  total length */
    u_short ip_id;                  /**<  identification */
    u_short ip_off;                 /**<  fragment offset field */
    #define IP_RF 0x8000            /**<  reserved fragment flag */
    #define IP_DF 0x4000            /**<  dont fragment flag */
    #define IP_MF 0x2000            /**<  more fragments flag */
    #define IP_OFFMASK 0x1fff       /**<  mask for fragmenting bits */
    u_char  ip_ttl;                 /**<  time to live */
    u_char  ip_p;                   /**<  protocol */
    u_short ip_sum;                 /**<  checksum */
    struct  in_addr ip_src,ip_dst;  /**<  source and dest address */
};
#define IP_HL(ip)           (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)            (((ip)->ip_vhl) >> 4)

/*  TCP header */
typedef u_int tcp_seq;

struct tcp_header {
    u_short th_sport;               /**<  source port */
    u_short th_dport;               /**<  destination port */
    tcp_seq th_seq;                 /**<  sequence number */
    tcp_seq th_ack;                 /**<  acknowledgement number */
    u_char  th_offx2;               /**<  data offset, rsvd */
    #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /**<  window */
    u_short th_sum;                 /**<  checksum */
    u_short th_urp;                 /**<  urgent pointer */
};

/*  CryptoBridge generic header */
struct cb_gen_header {
    u_char          version;                    /**<  protocol version */
    u_char          nonce[24];                  /**<  Crypto Nonce */
    u_short         payload_len;                /**<  encrypted payload length */
} __attribute__((packed));

/*  CryptoBridge type 1 header */
struct cb_type1_header {
    u_char          payload_type;               /**<  payload type */
    u_int           seqnum;                     /**<  Sequence Number*/
    u_char          ip_proto;                   /**<  backup of original ip protocol */
} __attribute__((packed));


extern uint16_t ip_checksum(const void *buf, size_t hdr_len); 

#endif
