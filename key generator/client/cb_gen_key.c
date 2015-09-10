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
 * @file:     cb_gen_key.c
 * @author:   Titouan Mesot
 * @date:     Jun, 30 2015
 * @Version:  0.1
 * @brief : This software generate public and private key for clients
 * 
 * crypt_bridge_gen_key is called by the initscript. It sould be call
 * once at the initialisation of the device. 
 * It generate and write the public and private key for the device 
 * in the configuration file in /etc/crypt_bridge/cb.conf
 * It also write some logs in the usb key used for initialisation. 
 */
 
#include <stdio.h>
#include <unistd.h>
#include <string.h> 
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <zmq.h>
#include <zmq_utils.h>
#include <sodium.h>

#define CB_KEY_READABLE 41

int get_br_device_ip(char *ip){
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, "br-br0", IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);   
    close(fd);
    strcpy(ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    return 0;
}
 
int get_node_id()
{
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

int write_client_key(char *my_pub_key, char *my_secret_key)
{
    char* buff = malloc(200); 
    int res = -1; 
    FILE *fp;
    fp=fopen("/etc/crypt_bridge/cb.conf", "a");
    if(fp == NULL){
        printf("Error: %d (%s)\n", errno, strerror(errno));
        exit(EXIT_FAILURE); 
    }
    fgets(buff, 100, fp); 
    fgets(buff, 100, fp); 
    fgets(buff, 100, fp); 
    res = fprintf(fp, "client_pub=%s\n", my_pub_key);
    fgets(buff, 100, fp); 
    res = fprintf(fp, "client_secret=%s\n", my_secret_key);
    fclose(fp); 
    free(buff);
    return res; 
}

int get_client_pub_key(char *my_pub_key)
{
    char*buff = malloc(100); 
    int res = -1; 
    FILE *fp;
    fp=fopen("/etc/crypt_bridge/cb.conf", "r");
        if(fp == NULL){
            printf("Error: %d (%s)\n", errno, strerror(errno));
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

int get_client_secret_key(char *my_secret_key)
{
    char*buff = malloc(200); 
    int res = -1; 
    FILE *fp;
    fp=fopen("/etc/crypt_bridge/cb.conf", "r");
        if(fp == NULL){
            printf("Error: %d (%s)\n", errno, strerror(errno));
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

int main(int argc, char **argv){
    char *my_pub_key = malloc(CB_KEY_READABLE);
    char *my_secret_key = malloc(CB_KEY_READABLE);
    if((get_client_pub_key(my_pub_key) != 1) && (get_client_secret_key(my_secret_key) !=1)){
        int rc = zmq_curve_keypair(my_pub_key, my_secret_key);
        assert (rc == 0);
        write_client_key(my_pub_key,my_secret_key); 
    }
    free (my_pub_key); 
    free (my_secret_key); 
    return 0;
}
