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

#include "microtcp.h"
#include "../utils/crc32.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

microtcp_sock_t 
microtcp_socket(int domain, int type, int protocol)
{
    microtcp_sock_t sock;
    
    // type and protocol check (must be UDP)
    if (type != SOCK_DGRAM || protocol != IPPROTO_UDP) {
        fprintf(stderr, "[microtcp_socket] Only UDP sockets are supported\n");
        sock.sd = -1;
        sock.state = INVALID;
        return sock;
    }

    memset(&sock, 0, sizeof(microtcp_sock_t));

    // UDP socket generation
    sock.sd = socket(domain, type, protocol);
    if (sock.sd < 0) {
        perror("[microtcp_socket] socket creation failed");
        sock.state = INVALID;
        return sock;
    }

    // inits
    sock.state = CLOSED;
    sock.init_win_size = MICROTCP_WIN_SIZE;
    sock.curr_win_size = MICROTCP_WIN_SIZE;

    // memory for recieve buffer and init buf_fill_level
    sock.recvbuf = malloc(MICROTCP_RECVBUF_LEN);
    if (!sock.recvbuf) {
        perror("[microtcp_socket] malloc for recieve buffer failed");
        close(sock.sd);
        sock.state = INVALID;
        return sock;
    }
    sock.buf_fill_level = 0;

    // inits
    sock.cwnd = MICROTCP_INIT_CWND;
    sock.ssthresh = MICROTCP_INIT_SSTHRESH;
    sock.seq_number = 0;
    sock.ack_number = 0;
    sock.packets_send = 0;
    sock.packets_received = 0;
    sock.packets_lost = 0;
    sock.bytes_send = 0;
    sock.bytes_received = 0;
    sock.bytes_lost = 0;

    printf("[microtcp_socket] created socket with sd: %d, state: CLOSED\n", sock.sd);

    return sock;
}

int 
microtcp_bind(microtcp_sock_t *socket,
                  const struct sockaddr *address,
                  socklen_t address_len)
{
    if (!socket || !address || socket->sd < 0) {
        return -1;
    }

    // Check if socket is already connected/bounded 
    if (socket->state != CLOSED) {
        fprintf(stderr, "[microtcp_bind] socket is not in CLOSED state\n");
        return -1;
    }

    // Call the underlying UDP bind and check if bind failed
    if (bind(socket->sd, address, address_len) < 0) {
        perror("[microtcp_bind] bind failed, bind < 0");
        return -1;
    }

    // After bind the socket is ready to accept connections 
    socket->state = LISTEN;
    printf("[microtcp_bind] created socket with sd: %d, state: LISTEN\n", socket->sd);
    sleep(3);

    return 0;
}

int microtcp_connect(microtcp_sock_t *socket,
                     const struct sockaddr *address,
                     socklen_t address_len)
{
    microtcp_header_t hdr, recv_hdr;
    ssize_t n;
    struct sockaddr_in from_addr;
    socklen_t from_len;
    uint32_t client_seq, server_seq;

    if (!socket || !address || socket->sd < 0) {
        return -1;
    }

    // Save peer address to help later the shutdown
    memcpy(&socket->peer_addr, address, address_len);
    socket->peer_addr_len = address_len;

    // Init sequence number (random for the connect)
    srand(time(NULL));
    socket->seq_number = rand() % 10000 + 1;
    socket->ack_number = 0;
    
    client_seq = socket->seq_number;

    /* Send SYN (update the microtcp header)*/
    memset(&hdr, 0, sizeof(hdr));
    hdr.seq_number = htonl(client_seq);
    hdr.control = htons(1 << 14);  // SYN=1, put 1 to 14th bit
    hdr.window = htons(MICROTCP_WIN_SIZE); // for later
    hdr.data_len = 0; // for later
    
    // Checksum
    hdr.checksum = 0;
    hdr.checksum = crc32((uint8_t*)&hdr, sizeof(microtcp_header_t));
    
    n = sendto(socket->sd, &hdr, sizeof(hdr), 0, address, address_len);
    if (n != sizeof(hdr)) {
        perror("[microtcp_connect]: header and SYN send failed");
        return -1;
    }
    
    printf("[microtcp_connect] SYN sent\n");

    // Receive SYN + ACK 
    from_len = sizeof(from_addr);    
    n = recvfrom(socket->sd, &recv_hdr, sizeof(recv_hdr), 0, (struct sockaddr*)&from_addr, &from_len);
    
    if (n < 0) {
        perror("[microtcp_connect] fail to receive SYN + ACK");
        return -1;
    }

    // Debug checksum
    uint32_t recv_crc = recv_hdr.checksum;
    recv_hdr.checksum = 0;
    uint32_t calc_crc = crc32((uint8_t*)&recv_hdr, sizeof(microtcp_header_t));
    if (recv_crc != calc_crc) {
        printf("[microtcp_connect] Warning: header received has bad checksum (continuing)\n");
    }

    // Check Control flags
    uint16_t ctrl = ntohs(recv_hdr.control);
    if (!(ctrl & (1 << 14)) || !(ctrl & (1 << 12))) {
        fprintf(stderr, "[microtcp_connect] not a SYN-ACK packet (handshake) \n");
        return -1;
    }

    // Check ACK number
    server_seq = ntohl(recv_hdr.seq_number);
    uint32_t recv_ack = ntohl(recv_hdr.ack_number);
    
    if (recv_ack != client_seq + 1) {
        fprintf(stderr, "[microtcp_connect] invalid ACK number (got %u, expected %u)\n", recv_ack, client_seq + 1);
        return -1;
    }

    // Update ack and seq numbers and init window size
    socket->ack_number = server_seq + 1;
    socket->seq_number = client_seq + 1;
    socket->init_win_size = ntohs(recv_hdr.window);
    socket->curr_win_size = socket->init_win_size;
    
    printf("[microtcp_connect] Received SYN: server_seq=%u, ACK: ack=%u\n", server_seq, recv_ack);

    /* Send ACK */
    memset(&hdr, 0, sizeof(hdr));
    hdr.seq_number = htonl(socket->seq_number);
    hdr.ack_number = htonl(socket->ack_number);
    hdr.control = htons(1 << 12);  // ACK=1
    hdr.window = htons(MICROTCP_WIN_SIZE);
    hdr.data_len = 0;
    
    // Checksum
    hdr.checksum = 0;
    hdr.checksum = crc32((uint8_t*)&hdr, sizeof(microtcp_header_t));

    
    n = sendto(socket->sd, &hdr, sizeof(hdr), 0, address, address_len);
    if (n != sizeof(hdr)) {
        perror("[microtcp_connect] fail to send ACK\n");
        return -1;
    }

    printf("[microtcp_connect] final ACK sent\n");
    sleep(3);

    // Connection established
    socket->state = ESTABLISHED;
    printf("[microsoft_connect] Connection ESTABLISHED\n\n");
    sleep(3);

    return 0;
}

int microtcp_accept(microtcp_sock_t *socket,
                    struct sockaddr *address,
                    socklen_t address_len)
{
    microtcp_header_t hdr, recv_hdr;
    ssize_t n;
    struct sockaddr_storage peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    uint32_t client_seq, server_seq;

    if (!socket || socket->sd < 0 || socket->state != LISTEN) {
        return -1;
    }


    /*Wait for SYN */
    sleep(3);
    n = recvfrom(socket->sd, &recv_hdr, sizeof(recv_hdr), 0,
                 (struct sockaddr*)&peer_addr, &peer_len);
    
    if (n < 0) {
        perror("[microtcp_accept] fail to receive SYN\n");
        return -1;
    }

    // Store peer address
    memcpy(&socket->peer_addr, &peer_addr, peer_len);
    socket->peer_addr_len = peer_len;

    // Debug checksum
    uint32_t recv_crc = recv_hdr.checksum;
    recv_hdr.checksum = 0;
    uint32_t calc_crc = crc32((uint8_t*)&recv_hdr, sizeof(microtcp_header_t));
    if (recv_crc != calc_crc) {
        printf("[microtcp_accept] Warning: header(SYN) has bad checksum (continuing)\n");
    }

    // Check SYN flag
    uint16_t ctrl = ntohs(recv_hdr.control);
    if (!(ctrl & (1 << 14))) {
        fprintf(stderr, "[microtcp_accept] expected SYN packet\n");
        return -1;
    }

    // Store client sequence number
    client_seq = ntohl(recv_hdr.seq_number);
    socket->ack_number = client_seq + 1;
    
    printf("[microtcp_accept] Received SYN (client_seq=%u)\n", client_seq);

    // update header and send SYN + ACK 
    srand(time(NULL));
    server_seq = rand() % 10000 + 1;
    socket->seq_number = server_seq;

    memset(&hdr, 0, sizeof(hdr));
    hdr.seq_number = htonl(server_seq);
    hdr.ack_number = htonl(socket->ack_number);
    hdr.control = htons((1 << 14) | (1 << 12));  // SYN=1, ACK=1
    hdr.window = htons(MICROTCP_WIN_SIZE);
    hdr.data_len = 0;
    
    // Checksum
    hdr.checksum = 0;
    hdr.checksum = crc32((uint8_t*)&hdr, sizeof(microtcp_header_t));

    // Send SYN-ACK
    sleep(3);
    
    n = sendto(socket->sd, &hdr, sizeof(hdr), 0,
               (struct sockaddr*)&peer_addr, peer_len);
    
    if (n != sizeof(hdr)) {
        perror("[microtcp_accept] fail to send header (SYN - ACK)");
        return -1;
    }
    
    printf("[microtcp_accept] SYN-ACK sent (server_seq=%u, ack=%u)\n",
           server_seq, socket->ack_number);

    /* 3. Wait for final ACK */
    sleep(3);
    n = recvfrom(socket->sd, &recv_hdr, sizeof(recv_hdr), 0,
                 (struct sockaddr*)&peer_addr, &peer_len);
    
    if (n < 0) {
        perror("[microtcp_accept] recv ACK failed");
        return -1;
    }

    // Debug checksum
    recv_crc = recv_hdr.checksum;
    recv_hdr.checksum = 0;
    calc_crc = crc32((uint8_t*)&recv_hdr, sizeof(microtcp_header_t));
    if (recv_crc != calc_crc) {
        printf("[microtcp_accept] Warning: ACK has bad checksum (continuing)\n");
    }

    // Check ACK flag
    ctrl = ntohs(recv_hdr.control);
    if (!(ctrl & (1 << 12))) {
        fprintf(stderr, "[microtcp_accept] expected ACK packet\n");
        return -1;
    }

    // Check ACK number
    uint32_t recv_ack = ntohl(recv_hdr.ack_number);
    if (recv_ack != server_seq + 1) {
        fprintf(stderr, "[microtcp_accept] wrong ACK number (got %u, expected %u)\n",
                recv_ack, server_seq + 1);
        return -1;
    }

    // Connection established
    socket->seq_number = server_seq + 1;
    socket->state = ESTABLISHED;
    socket->init_win_size = ntohs(recv_hdr.window);
    socket->curr_win_size = socket->init_win_size;
    
    // Store peer_address to address
    if (address != NULL && address_len >= peer_len) {
        memcpy(address, &peer_addr, peer_len);
    }

    printf("[microtcp_accept] Final seq=%u, ack=%u\n\n", 
           socket->seq_number, socket->ack_number);
    sleep(3);

    printf("[microtcp_accept] Connection ESTABLISHED with client\n");
    
    return 0;
}

int microtcp_shutdown(microtcp_sock_t *socket, int how)
{
    microtcp_header_t hdr, recv_hdr;
    ssize_t n;
    struct sockaddr_storage peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    uint32_t fin_seq, fin_ack;

    if (!socket || socket->sd < 0 || socket->state != ESTABLISHED) {
        return -1;
    }


    printf("[microtcp_shutdown] Starting  shutdown...\n");

    /* Client sends FIN */
    fin_seq = socket->seq_number;
    fin_ack = socket->ack_number;
    
    memset(&hdr, 0, sizeof(hdr));
    hdr.seq_number = htonl(fin_seq);
    hdr.ack_number = htonl(fin_ack);
    hdr.control = htons((1 << 15) | (1 << 12));  // FIN=1, ACK=1
    hdr.window = htons(socket->curr_win_size);
    hdr.data_len = 0;
    
    // Checksum
    hdr.checksum = 0;
    hdr.checksum = crc32((uint8_t*)&hdr, sizeof(microtcp_header_t));

    printf("[microtcp_shutdown] Sending FIN (seq=%u, ack=%u)...\n", fin_seq, fin_ack);
    sleep(3);
    
    n = sendto(socket->sd, &hdr, sizeof(hdr), 0,
               (struct sockaddr*)&socket->peer_addr, socket->peer_addr_len);
    
    if (n != sizeof(hdr)) {
        perror("[microtcp_shutdown] fail to send FIN");
        return -1;
    }
    
    socket->state = CLOSING_BY_HOST;
    printf("[microtcp_shutdown] FIN sent, state -> CLOSING_BY_HOST\n");

    /* Receive ACK */
    sleep(3);

    n = recvfrom(socket->sd, &recv_hdr, sizeof(recv_hdr), 0,
                 (struct sockaddr*)&peer_addr, &peer_len);
    
    if (n < 0) {
        perror("shutdown: recv ACK failed");
        return -1;
    }

    // Debug checksum
    uint32_t recv_crc = recv_hdr.checksum;
    recv_hdr.checksum = 0;
    uint32_t calc_crc = crc32((uint8_t*)&recv_hdr, sizeof(microtcp_header_t));
    if (recv_crc != calc_crc) {
        printf("[microtcp_shutdown] Warning: header has bad checksum (continuing)\n");
    }

    // Check ACK flag
    uint16_t ctrl = ntohs(recv_hdr.control);
    if (!(ctrl & (1 << 12))) {
        fprintf(stderr, "[microtcp_shutdown] expected ACK packet\n");
        return -1;
    }

    // Check ACK number (fin_seq + 1)
    uint32_t recv_ack = ntohl(recv_hdr.ack_number);
    if (recv_ack != fin_seq + 1) {
        printf("[microtcp_shutdown] Warning: ACK number mismatch (got %u, expected %u)\n",
               recv_ack, fin_seq + 1);
    }

    printf("[microtcp_shutdown] Received ACK, state -> CLOSING_BY_PEER (waiting for FIN)\n");

    /* Wait for FIN from server */
    printf("[microtcp_shutdown] Waiting for server's FIN...\n");
    sleep(3);

    n = recvfrom(socket->sd, &recv_hdr, sizeof(recv_hdr), 0, NULL, NULL);
    
    if (n < 0) {
        perror("shutdown: recv server FIN failed");
        return -1;
    }

    // Debug checksum
    recv_crc = recv_hdr.checksum;
    recv_hdr.checksum = 0;
    calc_crc = crc32((uint8_t*)&recv_hdr, sizeof(microtcp_header_t));
    if (recv_crc != calc_crc) {
        printf("[microtcp_shutdown] Warning: FIN has bad checksum (continuing)\n");
    }

    // Check FIN flag
    ctrl = ntohs(recv_hdr.control);
    if (!(ctrl & (1 << 15))) {
        fprintf(stderr, "[microtcp_shutdown] expected FIN packet\n");
        return -1;
    }

    uint32_t server_fin_seq = ntohl(recv_hdr.seq_number);
    printf("[microtcp_shutdown] Received FIN from server (seq=%u)\n", server_fin_seq);

    /* Send final ACK */
    memset(&hdr, 0, sizeof(hdr));
    hdr.seq_number = htonl(fin_seq + 1);         // Client seq+1
    hdr.ack_number = htonl(server_fin_seq + 1);  // Server fin seq+1
    hdr.control = htons(1 << 12);                // ACK=1
    hdr.window = htons(socket->curr_win_size);
    hdr.data_len = 0;
    
    // Checksum
    hdr.checksum = 0;
    hdr.checksum = crc32((uint8_t*)&hdr, sizeof(microtcp_header_t));

    printf("[microtcp_shutdown] Sending final ACK...\n");
    sleep(3);
    
    n = sendto(socket->sd, &hdr, sizeof(hdr), 0,
               (struct sockaddr*)&socket->peer_addr, socket->peer_addr_len);
    
    if (n != sizeof(hdr)) {
        perror("[microtcp_shutdown] fail to send ACK");
        return -1;
    }

    /* Close connection */
    socket->state = CLOSED;
    
    // close socket
    close(socket->sd);
    socket->sd = -1;
    printf("[microtcp_shutdown] Connection CLOSED \n\n");
    sleep(3);

    return 0;
}

ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags)
{
  /* Your code here */
}

ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  /* Your code here */
}
