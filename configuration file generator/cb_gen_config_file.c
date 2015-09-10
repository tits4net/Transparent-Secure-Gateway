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
 * @file:     cb_gen_config_file.c
 * @author:   Titouan Mesot
 * @date:     Jul, 5 2015
 * @Version:  0.1
 * @brief : This software generate the initialisation configuration file
 * 
 */

#include <string.h>
#include <stdio.h>
#include "zmq.h"

static int write_line (FILE *config, char *prompt, char *key)
{
    printf ("%s ", prompt);
    char value [256];
    if (fgets (value, 256, stdin) == NULL)
        return -1;
        
    if (strlen (value) && value [strlen (value) - 1] == '\n')
        value [strlen (value) - 1] = 0;
    if (*value)
        fputs(key, config);
        fputs("=", config);
        fputs(value, config);
        fputs("\n", config);
    return 0;
}

int main (void) 
{
   FILE *fp;
   int res = -1;
   fp = fopen("./cb.conf", "w+");
   printf("Creating crypt_bridge configuration file\n");
   res = write_line (fp, "Serveur IP (or hostname) : ", "server_ip");
   res = write_line (fp, "Node id : ", "node_name");
   res = write_line (fp, "Serveur Public Key : ", "server_pub");

   fclose(fp);
   if(res == 0)
	printf("Done OK\n"); 
   else
	printf("Error something goes wrong (write permission in this dir, libzmq installed ?"); 

  return 0; 

}

