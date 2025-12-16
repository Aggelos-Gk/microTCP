/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * You can use this file to write a test microTCP client.
 * This file is already inserted at the build system.
 */

#include "../lib/microtcp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    microtcp_sock_t sock;
    struct sockaddr_in server_addr;
    int shutdown = 0;
    
    // socket creation (IPv4 - UDP)
    sock = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock.state == INVALID) {
        fprintf(stderr, "[CLIENT] socket creation failed\n");
        return -1;
    }
    
    // Server address that client will connect with
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    // Connect
    printf("[CLIENT] Connecting to server: %s, port: %d\n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));
    if (microtcp_connect(&sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Connection failed\n");
        close(sock.sd);
        return -1;
    }
    
    printf("[CLIENT] Connected successfully to %s:%d!\n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port)); 
    sleep(1);
    
    // Shutdown
    printf("[CLIENT] Do you want to shutdown?\n    No  = 0\n    Yes = 1\n");
    scanf("%d", &shutdown);
    while (shutdown == 0){
        printf("[CLIENT] Do you want to shutdown?\n    No  = 0\n    Yes = 1\n");
        scanf("%d", &shutdown);
    }
    
    if (microtcp_shutdown(&sock, SHUT_RDWR) < 0) {
        fprintf(stderr, "[CLIENT]Shutdown failed - exit from connection\n");
        close(sock.sd);
        return -1;
    }
    
    printf("[CLIENT] Shutdown completed successfully!\n\n");
    
    return 0;
}