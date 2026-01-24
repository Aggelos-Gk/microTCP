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
#define TEST_DATA_SIZE 102400  // 100 KB για δοκιμή

int main() {
    microtcp_sock_t sock;
    struct sockaddr_in server_addr;
    uint8_t *send_buffer;
    ssize_t bytes_sent;
    size_t total_sent = 0;
    size_t remaining;
    
    /* ==================== ΔΗΜΙΟΥΡΓΙΑ SOCKET ==================== */
    printf("[CLIENT] Creating microTCP socket...\n");
    sock = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock.state == INVALID) {
        fprintf(stderr, "[CLIENT] Socket creation failed\n");
        return -1;
    }
    printf("[CLIENT] Socket created successfully (sd=%d)\n", sock.sd);

    /* ==================== ΔΙΕΥΘΥΝΣΗ SERVER ==================== */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    /* ==================== CONNECT TO SERVER ==================== */
    printf("[CLIENT] ========================================\n");
    printf("[CLIENT] Connecting to %s:%d\n", 
           inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));
    printf("[CLIENT] ========================================\n");
    
    if (microtcp_connect(&sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "[CLIENT] Connection failed\n");
        close(sock.sd);
        return -1;
    }
    
    printf("[CLIENT] ========================================\n");
    printf("[CLIENT] CONNECTED SUCCESSFULLY!\n");
    printf("[CLIENT] ========================================\n\n");

    /* ==================== ΔΗΜΙΟΥΡΓΙΑ TEST DATA ==================== */
    printf("[CLIENT] Preparing test data (%d bytes)...\n", TEST_DATA_SIZE);
    send_buffer = malloc(TEST_DATA_SIZE);
    if (!send_buffer) {
        fprintf(stderr, "[CLIENT] Failed to allocate send buffer\n");
        microtcp_shutdown(&sock, SHUT_RDWR);
        return -1;
    }
    
    // Γέμισμα buffer με test data (pattern: 0-255 επαναλαμβανόμενο)
    for (size_t i = 0; i < TEST_DATA_SIZE; i++) {
        send_buffer[i] = i % 256;
    }
    printf("[CLIENT] Test data prepared\n\n");

    /* ==================== ΑΠΟΣΤΟΛΗ ΔΕΔΟΜΕΝΩΝ ==================== */
    printf("[CLIENT] ========================================\n");
    printf("[CLIENT] Starting data transmission...\n");
    printf("[CLIENT] Total to send: %d bytes\n", TEST_DATA_SIZE);
    printf("[CLIENT] ========================================\n\n");
    
    remaining = TEST_DATA_SIZE;
    
    // Αποστολή σε chunks
    while (total_sent < TEST_DATA_SIZE) {
        size_t chunk_size = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : remaining;
        
        printf("[CLIENT] Sending chunk: %zu bytes (progress: %zu/%d)\n",
               chunk_size, total_sent, TEST_DATA_SIZE);
        
        bytes_sent = microtcp_send(&sock, send_buffer + total_sent, chunk_size, 0);
        
        if (bytes_sent < 0) {
            fprintf(stderr, "[CLIENT] Error sending data\n");
            free(send_buffer);
            microtcp_shutdown(&sock, SHUT_RDWR);
            return -1;
        }
        
        if (bytes_sent == 0) {
            fprintf(stderr, "[CLIENT] Warning: 0 bytes sent\n");
            continue;
        }
        
        total_sent += bytes_sent;
        remaining -= bytes_sent;
        
        printf("[CLIENT] Sent %zd bytes successfully (total: %zu/%d)\n\n",
               bytes_sent, total_sent, TEST_DATA_SIZE);
    }
    
    printf("[CLIENT] ========================================\n");
    printf("[CLIENT] DATA TRANSMISSION COMPLETED\n");
    printf("[CLIENT] Total bytes sent: %zu\n", total_sent);
    printf("[CLIENT] Packets sent: %lu, received: %lu, lost: %lu\n",
           sock.packets_send, sock.packets_received, sock.packets_lost);
    printf("[CLIENT] ========================================\n\n");

    /* ==================== ΚΑΘΑΡΙΣΜΟΣ BUFFER ==================== */
    free(send_buffer);

    /* ==================== USER CONFIRMATION FOR SHUTDOWN ==================== */
    printf("[CLIENT] ========================================\n");
    printf("[CLIENT] Data transmission complete.\n");
    printf("[CLIENT] Press ENTER to initiate shutdown...\n");
    printf("[CLIENT] ========================================\n");
    getchar();  // Clear input buffer
    getchar();  // Wait for user

    /* ==================== SHUTDOWN CONNECTION ==================== */
    printf("[CLIENT] ========================================\n");
    printf("[CLIENT] Initiating connection shutdown...\n");
    printf("[CLIENT] ========================================\n");
    
    if (microtcp_shutdown(&sock, SHUT_RDWR) < 0) {
        fprintf(stderr, "[CLIENT] Shutdown failed\n");
        close(sock.sd);
        return -1;
    }
    
    printf("[CLIENT] ========================================\n");
    printf("[CLIENT] SHUTDOWN COMPLETED SUCCESSFULLY\n");
    printf("[CLIENT] ========================================\n");
    printf("[CLIENT] Final statistics:\n");
    printf("[CLIENT]   - Packets sent: %lu\n", sock.packets_send);
    printf("[CLIENT]   - Packets received: %lu\n", sock.packets_received);
    printf("[CLIENT]   - Packets lost: %lu\n", sock.packets_lost);
    printf("[CLIENT]   - Bytes sent: %lu\n", sock.bytes_send);
    printf("[CLIENT]   - Bytes received: %lu\n", sock.bytes_received);
    printf("[CLIENT] ========================================\n");
    
    return 0;
}