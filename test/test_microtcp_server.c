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
#include "../utils/crc32.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFFER_SIZE 8192

int main() {
    microtcp_sock_t sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    uint8_t *recv_buffer;
    ssize_t bytes_received;
    size_t total_received = 0;
    
    /* ==================== ΔΗΜΙΟΥΡΓΙΑ SOCKET ==================== */
    printf("[SERVER] Creating microTCP socket...\n");
    sock = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock.state == INVALID) {
        fprintf(stderr, "[SERVER] Socket creation failed\n");
        return -1;
    }
    printf("[SERVER] Socket created successfully (sd=%d)\n\n", sock.sd);

    /* ==================== BIND ==================== */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    if (microtcp_bind(&sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "[SERVER] Bind failed\n");
        close(sock.sd);
        return -1;
    }
    
    printf("[SERVER] ========================================\n");
    printf("[SERVER] Listening on 0.0.0.0:%d\n", ntohs(server_addr.sin_port));
    printf("[SERVER] ========================================\n\n");

    /* ==================== ACCEPT CONNECTION ==================== */
    printf("[SERVER] Waiting for client connection...\n");
    client_len = sizeof(client_addr);
    
    if (microtcp_accept(&sock, (struct sockaddr*)&client_addr, client_len) < 0) {
        fprintf(stderr, "[SERVER] Accept failed\n");
        close(sock.sd);
        return -1;
    }
    
    // Εκτύπωση πληροφοριών client
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    printf("[SERVER] ========================================\n");
    printf("[SERVER] Client connected from %s:%d\n", 
           client_ip, ntohs(client_addr.sin_port));
    printf("[SERVER] ========================================\n\n");

    /* ==================== ΔΗΜΙΟΥΡΓΙΑ RECEIVE BUFFER ==================== */
    recv_buffer = malloc(BUFFER_SIZE);
    if (!recv_buffer) {
        fprintf(stderr, "[SERVER] Failed to allocate receive buffer\n");
        close(sock.sd);
        return -1;
    }
    
    /* ==================== ΛΗΨΗ ΔΕΔΟΜΕΝΩΝ ==================== */
    printf("[SERVER] Starting data reception...\n");
    printf("[SERVER] ========================================\n");
    
    // Λήψη δεδομένων σε βρόχο μέχρι να τερματίσει ο client
    while (sock.state == ESTABLISHED) {
        
        // Καθαρισμός buffer
        memset(recv_buffer, 0, BUFFER_SIZE);
        
        // Λήψη δεδομένων
        bytes_received = microtcp_recv(&sock, recv_buffer, BUFFER_SIZE, 0);
        
        // Έλεγχος για σφάλματα ή τερματισμό
        if (bytes_received < 0) {
            if (sock.state == CLOSING_BY_PEER) {
                printf("[SERVER] Connection closing by peer (FIN received)\n");
                break;
            }
            fprintf(stderr, "[SERVER] Error receiving data\n");
            break;
        }
        
        // Αν δεν λάβαμε τίποτα, συνέχισε
        if (bytes_received == 0) {
            continue;
        }
        
        total_received += bytes_received;
        
        // Εκτύπωση προόδου
        printf("[SERVER] Received %zd bytes (total: %zu bytes)\n", 
               bytes_received, total_received);
        
        // Προαιρετικά: εκτύπωση δείγματος δεδομένων (πρώτα 50 bytes)
        printf("[SERVER] Sample data: ");
        size_t sample_size = (bytes_received < 50) ? bytes_received : 50;
        for (size_t i = 0; i < sample_size; i++) {
            if (recv_buffer[i] >= 32 && recv_buffer[i] <= 126) {
                printf("%c", recv_buffer[i]);
            } else {
                printf(".");
            }
        }
        if (bytes_received > 50) {
            printf("...");
        }
        printf("\n\n");
    }
    
    printf("[SERVER] ========================================\n");
    printf("[SERVER] DATA RECEPTION COMPLETED\n");
    printf("[SERVER] Total bytes received: %zu\n", total_received);
    printf("[SERVER] ========================================\n\n");

    /* ==================== ΧΕΙΡΙΣΜΟΣ FIN TERMINATION ==================== */
    // Αν είμαστε σε CLOSING_BY_PEER, πρέπει να ολοκληρώσουμε το shutdown
    if (sock.state == CLOSING_BY_PEER) {
        printf("[SERVER] ========================================\n");
        printf("[SERVER] Handling connection termination...\n");
        printf("[SERVER] ========================================\n");
        
        microtcp_header_t hdr, ack_hdr, fin_hdr;
        ssize_t n;
        
        // Βρόχος για χειρισμό FIN termination
        while (sock.state != CLOSED) {
            
            // Περιμένουμε για πακέτα
            n = recvfrom(sock.sd, &hdr, sizeof(hdr), 0, NULL, NULL);
            
            if (n < 0) {
                perror("[SERVER] recvfrom failed during shutdown");
                break;
            }
            
            uint16_t ctrl = ntohs(hdr.control);
            
            // Αν λάβαμε FIN
            if (ctrl & (1 << 15)) {
                printf("[SERVER] Received FIN from client\n");
                
                // 1. Στείλε ACK για FIN
                memset(&ack_hdr, 0, sizeof(ack_hdr));
                ack_hdr.seq_number = htonl(sock.seq_number);
                ack_hdr.ack_number = htonl(ntohl(hdr.seq_number) + 1);
                ack_hdr.control = htons(1 << 12);  // ACK=1
                ack_hdr.window = htons(sock.curr_win_size);
                ack_hdr.data_len = 0;
                ack_hdr.future_use0 = 0;
                ack_hdr.future_use1 = 0;
                ack_hdr.future_use2 = 0;
                ack_hdr.checksum = 0;
                ack_hdr.checksum = crc32((uint8_t*)&ack_hdr, sizeof(microtcp_header_t));
                
                sendto(sock.sd, &ack_hdr, sizeof(ack_hdr), 0,
                       (struct sockaddr*)&sock.peer_addr, sock.peer_addr_len);
                
                printf("[SERVER] Sent ACK for FIN\n");
                
                // 2. Στείλε δικό μας FIN
                memset(&fin_hdr, 0, sizeof(fin_hdr));
                fin_hdr.seq_number = htonl(sock.seq_number);
                fin_hdr.ack_number = htonl(ntohl(hdr.seq_number) + 1);
                fin_hdr.control = htons((1 << 15) | (1 << 12));  // FIN=1, ACK=1
                fin_hdr.window = htons(sock.curr_win_size);
                fin_hdr.data_len = 0;
                fin_hdr.future_use0 = 0;
                fin_hdr.future_use1 = 0;
                fin_hdr.future_use2 = 0;
                fin_hdr.checksum = 0;
                fin_hdr.checksum = crc32((uint8_t*)&fin_hdr, sizeof(microtcp_header_t));
                
                sendto(sock.sd, &fin_hdr, sizeof(fin_hdr), 0,
                       (struct sockaddr*)&sock.peer_addr, sock.peer_addr_len);
                
                printf("[SERVER] Sent FIN\n");
                
                // Ενημέρωση state
                // Παραμένει σε CLOSING_BY_PEER μέχρι να λάβει ACK
            }
            
            // Αν λάβαμε ACK και είμαστε σε CLOSING_BY_PEER
            if ((ctrl & (1 << 12)) && sock.state == CLOSING_BY_PEER) {
                // Έλεγχος ότι δεν είναι SYN ή FIN (μόνο ACK)
                if (!(ctrl & (1 << 15)) && !(ctrl & (1 << 14))) {
                    printf("[SERVER] Received final ACK\n");
                    sock.state = CLOSED;
                    break;
                }
            }
        }
    }

    /* ==================== ΚΑΘΑΡΙΣΜΟΣ ==================== */
    free(recv_buffer);
    
    if (sock.recvbuf) {
        free(sock.recvbuf);
    }
    
    close(sock.sd);
    
    printf("[SERVER] ========================================\n");
    printf("[SERVER] CONNECTION CLOSED SUCCESSFULLY\n");
    printf("[SERVER] ========================================\n");
    printf("[SERVER] Final statistics:\n");
    printf("[SERVER]   - Total bytes received: %zu\n", total_received);
    printf("[SERVER]   - Packets sent: %lu\n", sock.packets_send);
    printf("[SERVER]   - Packets received: %lu\n", sock.packets_received);
    printf("[SERVER]   - Bytes sent: %lu\n", sock.bytes_send);
    printf("[SERVER]   - Bytes received: %lu\n", sock.bytes_received);
    printf("[SERVER] ========================================\n");
    printf("[SERVER] SERVER TERMINATED SUCCESSFULLY\n");
    printf("[SERVER] ========================================\n");
    
    return 0;
}