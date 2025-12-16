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
 * You can use this file to write a test microTCP server.
 * This file is already inserted at the build system.
 */

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

#include "../lib/microtcp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    microtcp_sock_t sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
        
    // Socket creation (IPv4 - UDP)
    sock = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock.state == INVALID) {
        fprintf(stderr, "[SERVER] socket creation failed\n");
        return -1;
    }

    sleep(3);

    // Bind
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    if (microtcp_bind(&sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock.sd);
        fprintf(stderr, "[SERVER] bind failed\n");
        return -1;
    }
    
    printf("[SERVER] Listening on port %d...\n", ntohs(server_addr.sin_port));
    sock.state = LISTEN;
    
    sleep(3);

    // Accept 
    printf("[SERVER] Waiting for client connection...\n");
    sleep(3);
    client_len = sizeof(client_addr);
    
    if (microtcp_accept(&sock, (struct sockaddr*)&client_addr, &client_len) < 0) {
        fprintf(stderr, "Accept failed\n");
        close(sock.sd);
        return -1;
    }
    
    printf("[SERVER] Client connected successfully!\n");
    
    while (sock.state != CLOSED) {

    microtcp_header_t hdr;
    ssize_t n;
    
    // Wait for packets
    n = recvfrom(sock.sd, &hdr, sizeof(hdr), 0, NULL, NULL);
    
    if (n < 0) {
        perror("[SERVER] recvfrom failed");
        break;
    }
    
    // Debug
    uint16_t ctrl = ntohs(hdr.control);
    
    //if FIN
    if (ctrl & (1 << 15)) {  
        printf("[SERVER] Received FIN from client\n");
        sleep(1);
        // 1. Στείλε ACK για FIN
        microtcp_header_t ack_hdr;
        memset(&ack_hdr, 0, sizeof(ack_hdr));
        ack_hdr.seq_number = htonl(sock.seq_number);
        ack_hdr.ack_number = htonl(ntohl(hdr.seq_number) + 1);
        ack_hdr.control = htons(1 << 12);  // ACK=1
        ack_hdr.window = htons(sock.curr_win_size);
        ack_hdr.data_len = 0;
        
        
        
        sendto(sock.sd, &ack_hdr, sizeof(ack_hdr), 0,
               (struct sockaddr*)&sock.peer_addr, sock.peer_addr_len);
        
        printf("[SERVER] Sent ACK for FIN\n");
        sleep(1);

        // Send FIN
        microtcp_header_t fin_hdr;
        memset(&fin_hdr, 0, sizeof(fin_hdr));
        fin_hdr.seq_number = htonl(sock.seq_number);
        fin_hdr.ack_number = htonl(ntohl(hdr.seq_number) + 1);
        fin_hdr.control = htons((1 << 15) | (1 << 12));  // FIN=1, ACK=1
        fin_hdr.window = htons(sock.curr_win_size);
        fin_hdr.data_len = 0;
        
        sendto(sock.sd, &fin_hdr, sizeof(fin_hdr), 0,
               (struct sockaddr*)&sock.peer_addr, sock.peer_addr_len);
        
        printf("[SERVER] Sent FIN\n");
        sock.state = CLOSING_BY_PEER;
    }
    
    // if ACK then CLOSE
    if (ctrl & (1 << 12) && sock.state == CLOSING_BY_PEER) {
        printf("[SERVER] Received ACK\n");
        sock.state = CLOSED;
        break;
    }
}
    
    sleep(3);
    
    close(sock.sd);
    printf("[SERVER] socket closed\n");
        
    return 0;
}