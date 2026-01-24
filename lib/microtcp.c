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

    // Βασικά inits
    sock.state = CLOSED;
    sock.init_win_size = MICROTCP_WIN_SIZE;
    sock.curr_win_size = MICROTCP_WIN_SIZE;

    // Receive buffer
    sock.recvbuf = malloc(MICROTCP_RECVBUF_LEN);
    if (!sock.recvbuf) {
        perror("[microtcp_socket] malloc for receive buffer failed");
        close(sock.sd);
        sock.state = INVALID;
        return sock;
    }
    sock.buf_fill_level = 0;

    // Congestion control - ΑΡΧΙΚΟΠΟΙΗΣΗ
    sock.cwnd = MICROTCP_INIT_CWND;          // Π.χ. 3 * MSS
    sock.ssthresh = MICROTCP_INIT_SSTHRESH;  // Π.χ. 65535
    sock.cc_state = 0;                       // 0 = SLOW_START

    // Duplicate ACK tracking για fast retransmit
    sock.dup_ack_count = 0;
    sock.last_ack_received = 0;

    // Peer window size για flow control
    sock.peer_win_size = 0;  // Θα οριστεί κατά το handshake

    // Sequence numbers
    sock.seq_number = 0;    // Θα γίνει τυχαίος κατά το connect/accept
    sock.ack_number = 0;

    // Στατιστικά
    sock.packets_send = 0;
    sock.packets_received = 0;
    sock.packets_lost = 0;
    sock.bytes_send = 0;
    sock.bytes_received = 0;
    sock.bytes_lost = 0;

    // Peer address (αρχικοποίηση)
    memset(&sock.peer_addr, 0, sizeof(struct sockaddr_storage));
    sock.peer_addr_len = 0;

    printf("[microtcp_socket] created socket with sd: %d, state: CLOSED\n", sock.sd);
    printf("[microtcp_socket] Congestion control initialized: cwnd=%u, ssthresh=%u\n",
           sock.cwnd, sock.ssthresh);

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
        fprintf(stderr, "[microtcp_connect] Invalid socket or address\n");
        return -1;
    }

    /* ==================== ΒΗΜΑ 1: ΑΠΟΘΗΚΕΥΣΗ PEER ADDRESS ==================== */
    memcpy(&socket->peer_addr, address, address_len);
    socket->peer_addr_len = address_len;
    
    printf("[microtcp_connect] Peer address saved (addr_len=%d)\n", address_len);

    /* ==================== ΒΗΜΑ 2: ΑΡΧΙΚΟΠΟΙΗΣΗ SEQUENCE NUMBER ==================== */
    // Τυχαίος 32-bit αριθμός για το αρχικό sequence number
    srand(time(NULL) ^ getpid());
    socket->seq_number = (rand() << 16) | rand();
    socket->ack_number = 0;
    
    client_seq = socket->seq_number;
    printf("[microtcp_connect] Initialized sequence number: %u\n", client_seq);

    /* ==================== ΒΗΜΑ 3: ΑΠΟΣΤΟΛΗ SYN ==================== */
    // Δημιουργία SYN πακέτου για το 3-way handshake
    memset(&hdr, 0, sizeof(hdr));
    hdr.seq_number = htonl(client_seq);
    hdr.ack_number = 0;  // Δεν υπάρχει ACK στο πρώτο SYN
    hdr.control = htons(1 << 14);  // SYN=1 (bit 14)
    hdr.window = htons(socket->curr_win_size);  // Ανακοίνωση του δικού μας window
    hdr.data_len = 0;  // Κανένα payload
    hdr.future_use0 = 0;
    hdr.future_use1 = 0;
    hdr.future_use2 = 0;
    
    // Υπολογισμός checksum για το header
    hdr.checksum = 0;
    hdr.checksum = crc32((uint8_t*)&hdr, sizeof(microtcp_header_t));
    
    printf("[microtcp_connect] Sending SYN: seq=%u, window=%u\n", 
           client_seq, socket->curr_win_size);
    
    n = sendto(socket->sd, &hdr, sizeof(hdr), 0, address, address_len);
    if (n != sizeof(hdr)) {
        perror("[microtcp_connect] SYN send failed");
        return -1;
    }
    
    socket->packets_send++;
    socket->bytes_send += sizeof(hdr);
    printf("[microtcp_connect] SYN sent successfully\n");

    /* ==================== ΒΗΜΑ 4: ΛΗΨΗ SYN-ACK ==================== */
    // Αναμονή για SYN-ACK από τον server (blocking)
    from_len = sizeof(from_addr);
    printf("[microtcp_connect] Waiting for SYN-ACK...\n");
    
    n = recvfrom(socket->sd, &recv_hdr, sizeof(recv_hdr), 0, 
                 (struct sockaddr*)&from_addr, &from_len);
    
    if (n < 0) {
        perror("[microtcp_connect] Failed to receive SYN-ACK");
        return -1;
    }
    
    socket->packets_received++;
    socket->bytes_received += n;

    /* ==================== ΒΗΜΑ 5: ΕΛΕΓΧΟΣ CHECKSUM ==================== */
    // Έλεγχος ακεραιότητας του SYN-ACK πακέτου
    uint32_t recv_crc = recv_hdr.checksum;
    recv_hdr.checksum = 0;
    uint32_t calc_crc = crc32((uint8_t*)&recv_hdr, sizeof(microtcp_header_t));
    
    if (recv_crc != calc_crc) {
        fprintf(stderr, "[microtcp_connect] CHECKSUM MISMATCH - dropping packet\n");
        fprintf(stderr, "[microtcp_connect] Received: 0x%08X, Calculated: 0x%08X\n", 
                recv_crc, calc_crc);
        return -1;
    }
    printf("[microtcp_connect] Checksum OK (0x%08X)\n", recv_crc);

    /* ==================== ΒΗΜΑ 6: ΕΛΕΓΧΟΣ CONTROL FLAGS ==================== */
    // Επαλήθευση ότι το πακέτο είναι SYN-ACK (bits 14 και 12)
    uint16_t ctrl = ntohs(recv_hdr.control);
    
    if (!(ctrl & (1 << 14))) {
        fprintf(stderr, "[microtcp_connect] Missing SYN flag\n");
        return -1;
    }
    if (!(ctrl & (1 << 12))) {
        fprintf(stderr, "[microtcp_connect] Missing ACK flag\n");
        return -1;
    }
    printf("[microtcp_connect] Control flags: SYN=1, ACK=1 (OK)\n");

    /* ==================== ΒΗΜΑ 7: ΕΛΕΓΧΟΣ ACK NUMBER ==================== */
    // Επαλήθευση ότι ο server επιβεβαιώνει το δικό μας SYN
    server_seq = ntohl(recv_hdr.seq_number);
    uint32_t recv_ack = ntohl(recv_hdr.ack_number);
    
    if (recv_ack != client_seq + 1) {
        fprintf(stderr, "[microtcp_connect] Invalid ACK number\n");
        fprintf(stderr, "[microtcp_connect] Got: %u, Expected: %u\n", 
                recv_ack, client_seq + 1);
        return -1;
    }
    printf("[microtcp_connect] SYN-ACK received: server_seq=%u, ack=%u\n", 
           server_seq, recv_ack);

    /* ==================== ΒΗΜΑ 8: ΕΝΗΜΕΡΩΣΗ SOCKET STATE ==================== */
    // Ενημέρωση των sequence/ack numbers για τη σύνδεση
    socket->seq_number = client_seq + 1;  // Το επόμενο δικό μας sequence
    socket->ack_number = server_seq + 1;  // Περιμένουμε αυτό από τον server
    
    // Αποθήκευση του server window size για flow control
    socket->init_win_size = ntohs(recv_hdr.window);
    socket->curr_win_size = socket->init_win_size;
    socket->peer_win_size = socket->init_win_size;
    
    printf("[microtcp_connect] Server window: %u bytes\n", socket->init_win_size);

    /* ==================== ΒΗΜΑ 9: ΑΠΟΣΤΟΛΗ ΤΕΛΙΚΟΥ ACK ==================== */
    // Ολοκλήρωση του 3-way handshake με τελικό ACK
    memset(&hdr, 0, sizeof(hdr));
    hdr.seq_number = htonl(socket->seq_number);
    hdr.ack_number = htonl(socket->ack_number);
    hdr.control = htons(1 << 12);  // ACK=1 (όχι SYN πια)
    hdr.window = htons(socket->curr_win_size);  // Επιβεβαίωση του δικού μας window
    hdr.data_len = 0;
    hdr.future_use0 = 0;
    hdr.future_use1 = 0;
    hdr.future_use2 = 0;
    
    // Υπολογισμός checksum
    hdr.checksum = 0;
    hdr.checksum = crc32((uint8_t*)&hdr, sizeof(microtcp_header_t));
    
    printf("[microtcp_connect] Sending final ACK: seq=%u, ack=%u, window=%u\n",
           socket->seq_number, socket->ack_number, socket->curr_win_size);
    
    n = sendto(socket->sd, &hdr, sizeof(hdr), 0, address, address_len);
    if (n != sizeof(hdr)) {
        perror("[microtcp_connect] Final ACK send failed");
        return -1;
    }
    
    socket->packets_send++;
    socket->bytes_send += sizeof(hdr);
    printf("[microtcp_connect] Final ACK sent\n");

    /* ==================== ΒΗΜΑ 10: ΟΛΟΚΛΗΡΩΣΗ HANDSHAKE ==================== */
    socket->state = ESTABLISHED;
    
    printf("[microtcp_connect] ========================================\n");
    printf("[microtcp_connect] CONNECTION ESTABLISHED SUCCESSFULLY\n");
    printf("[microtcp_connect] Client seq: %u, Client ack: %u\n", 
           socket->seq_number, socket->ack_number);
    printf("[microtcp_connect] Server window: %u, Peer window: %u\n",
           socket->init_win_size, socket->peer_win_size);
    printf("[microtcp_connect] ========================================\n\n");

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
        fprintf(stderr, "[microtcp_accept] Invalid socket or not in LISTEN state\n");
        return -1;
    }

    /* ==================== ΒΗΜΑ 1: ΛΗΨΗ SYN ==================== */
    // Αναμονή για SYN από τον client (blocking)
    printf("[microtcp_accept] Waiting for SYN...\n");
    
    n = recvfrom(socket->sd, &recv_hdr, sizeof(recv_hdr), 0,
                 (struct sockaddr*)&peer_addr, &peer_len);
    
    if (n < 0) {
        perror("[microtcp_accept] Failed to receive SYN");
        return -1;
    }
    
    socket->packets_received++;
    socket->bytes_received += n;

    /* ==================== ΒΗΜΑ 2: ΑΠΟΘΗΚΕΥΣΗ PEER ADDRESS ==================== */
    memcpy(&socket->peer_addr, &peer_addr, peer_len);
    socket->peer_addr_len = peer_len;
    
    printf("[microtcp_accept] Peer address stored (peer_len=%d)\n", peer_len);

    /* ==================== ΒΗΜΑ 3: ΕΛΕΓΧΟΣ CHECKSUM ==================== */
    // Έλεγχος ακεραιότητας του SYN πακέτου
    uint32_t recv_crc = recv_hdr.checksum;
    recv_hdr.checksum = 0;
    uint32_t calc_crc = crc32((uint8_t*)&recv_hdr, sizeof(microtcp_header_t));
    
    if (recv_crc != calc_crc) {
        fprintf(stderr, "[microtcp_accept] CHECKSUM MISMATCH - dropping packet\n");
        fprintf(stderr, "[microtcp_accept] Received: 0x%08X, Calculated: 0x%08X\n",
                recv_crc, calc_crc);
        return -1;
    }
    printf("[microtcp_accept] Checksum OK (0x%08X)\n", recv_crc);

    /* ==================== ΒΗΜΑ 4: ΕΛΕΓΧΟΣ SYN FLAG ==================== */
    // Επαλήθευση ότι το πακέτο είναι SYN (bit 14)
    uint16_t ctrl = ntohs(recv_hdr.control);
    if (!(ctrl & (1 << 14))) {
        fprintf(stderr, "[microtcp_accept] Missing SYN flag\n");
        return -1;
    }
    printf("[microtcp_accept] Control flags: SYN=1 (OK)\n");

    /* ==================== ΒΗΜΑ 5: ΑΠΟΘΗΚΕΥΣΗ CLIENT SEQUENCE ==================== */
    // Αποθήκευση του client sequence number
    client_seq = ntohl(recv_hdr.seq_number);
    socket->ack_number = client_seq + 1;  // Περιμένουμε το επόμενο από τον client
    
    // Αποθήκευση του client window size για flow control
    socket->peer_win_size = ntohs(recv_hdr.window);
    
    printf("[microtcp_accept] Received SYN: client_seq=%u, client_window=%u\n", 
           client_seq, socket->peer_win_size);

    /* ==================== ΒΗΜΑ 6: ΑΡΧΙΚΟΠΟΙΗΣΗ SERVER SEQUENCE ==================== */
    // Τυχαίος 32-bit αριθμός για το server sequence number
    srand(time(NULL) ^ getpid());
    socket->seq_number = (rand() << 16) | rand();
    server_seq = socket->seq_number;
    
    printf("[microtcp_accept] Initialized server sequence: %u\n", server_seq);

    /* ==================== ΒΗΜΑ 7: ΑΠΟΣΤΟΛΗ SYN-ACK ==================== */
    // Δημιουργία SYN-ACK πακέτου
    memset(&hdr, 0, sizeof(hdr));
    hdr.seq_number = htonl(server_seq);
    hdr.ack_number = htonl(socket->ack_number);
    hdr.control = htons((1 << 14) | (1 << 12));  // SYN=1, ACK=1
    hdr.window = htons(socket->curr_win_size);  // Ανακοίνωση του δικού μας window
    hdr.data_len = 0;
    hdr.future_use0 = 0;
    hdr.future_use1 = 0;
    hdr.future_use2 = 0;
    
    // Υπολογισμός checksum
    hdr.checksum = 0;
    hdr.checksum = crc32((uint8_t*)&hdr, sizeof(microtcp_header_t));
    
    printf("[microtcp_accept] Sending SYN-ACK: seq=%u, ack=%u, window=%u\n",
           server_seq, socket->ack_number, socket->curr_win_size);
    
    n = sendto(socket->sd, &hdr, sizeof(hdr), 0,
               (struct sockaddr*)&peer_addr, peer_len);
    
    if (n != sizeof(hdr)) {
        perror("[microtcp_accept] Failed to send SYN-ACK");
        return -1;
    }
    
    socket->packets_send++;
    socket->bytes_send += sizeof(hdr);
    printf("[microtcp_accept] SYN-ACK sent successfully\n");

    /* ==================== ΒΗΜΑ 8: ΛΗΨΗ ΤΕΛΙΚΟΥ ACK ==================== */
    // Αναμονή για το τελικό ACK από τον client (blocking)
    printf("[microtcp_accept] Waiting for final ACK...\n");
    
    n = recvfrom(socket->sd, &recv_hdr, sizeof(recv_hdr), 0,
                 (struct sockaddr*)&peer_addr, &peer_len);
    
    if (n < 0) {
        perror("[microtcp_accept] Failed to receive final ACK");
        return -1;
    }
    
    socket->packets_received++;
    socket->bytes_received += n;

    /* ==================== ΒΗΜΑ 9: ΕΛΕΓΧΟΣ CHECKSUM ΤΕΛΙΚΟΥ ACK ==================== */
    // Έλεγχος ακεραιότητας του ACK πακέτου
    recv_crc = recv_hdr.checksum;
    recv_hdr.checksum = 0;
    calc_crc = crc32((uint8_t*)&recv_hdr, sizeof(microtcp_header_t));
    
    if (recv_crc != calc_crc) {
        fprintf(stderr, "[microtcp_accept] ACK CHECKSUM MISMATCH - dropping packet\n");
        fprintf(stderr, "[microtcp_accept] Received: 0x%08X, Calculated: 0x%08X\n",
                recv_crc, calc_crc);
        return -1;
    }
    printf("[microtcp_accept] ACK Checksum OK (0x%08X)\n", recv_crc);

    /* ==================== ΒΗΜΑ 10: ΕΛΕΓΧΟΣ ACK FLAG ==================== */
    // Επαλήθευση ότι το πακέτο είναι ACK (bit 12)
    ctrl = ntohs(recv_hdr.control);
    if (!(ctrl & (1 << 12))) {
        fprintf(stderr, "[microtcp_accept] Missing ACK flag\n");
        return -1;
    }
    
    // Επιβεβαίωση ότι ΔΕΝ είναι SYN (θα έπρεπε να είναι μόνο ACK)
    if (ctrl & (1 << 14)) {
        fprintf(stderr, "[microtcp_accept] Warning: Unexpected SYN flag in final ACK\n");
    }
    printf("[microtcp_accept] Control flags: ACK=1 (OK)\n");

    /* ==================== ΒΗΜΑ 11: ΕΛΕΓΧΟΣ ACK NUMBER ==================== */
    // Επαλήθευση ότι ο client επιβεβαιώνει το δικό μας SYN
    uint32_t recv_ack = ntohl(recv_hdr.ack_number);
    if (recv_ack != server_seq + 1) {
        fprintf(stderr, "[microtcp_accept] Invalid ACK number\n");
        fprintf(stderr, "[microtcp_accept] Got: %u, Expected: %u\n",
                recv_ack, server_seq + 1);
        return -1;
    }
    printf("[microtcp_accept] Final ACK received: ack=%u\n", recv_ack);

    /* ==================== ΒΗΜΑ 12: ΕΝΗΜΕΡΩΣΗ SOCKET STATE ==================== */
    // Ενημέρωση των sequence numbers για τη σύνδεση
    socket->seq_number = server_seq + 1;  // Το επόμενο δικό μας sequence
    // socket->ack_number παραμένει client_seq + 1 (ήδη ορίστηκε στο ΒΗΜΑ 5)
    
    // Αποθήκευση του client window size (ενημερώθηκε από το τελικό ACK)
    socket->init_win_size = ntohs(recv_hdr.window);
    socket->curr_win_size = socket->init_win_size;
    socket->peer_win_size = ntohs(recv_hdr.window);
    
    printf("[microtcp_accept] Client window: %u bytes\n", socket->peer_win_size);

    /* ==================== ΒΗΜΑ 13: ΕΠΙΣΤΡΟΦΗ PEER ADDRESS ==================== */
    // Αποθήκευση της διεύθυνσης του peer στο address buffer του χρήστη
    if (address != NULL && address_len >= peer_len) {
        memcpy(address, &peer_addr, peer_len);
    }

    /* ==================== ΒΗΜΑ 14: ΟΛΟΚΛΗΡΩΣΗ HANDSHAKE ==================== */
    socket->state = ESTABLISHED;
    
    printf("[microtcp_accept] ========================================\n");
    printf("[microtcp_accept] CONNECTION ESTABLISHED SUCCESSFULLY\n");
    printf("[microtcp_accept] Server seq: %u, Server ack: %u\n",
           socket->seq_number, socket->ack_number);
    printf("[microtcp_accept] Client window: %u, Peer window: %u\n",
           socket->init_win_size, socket->peer_win_size);
    printf("[microtcp_accept] ========================================\n\n");

    return 0;
}

int microtcp_shutdown(microtcp_sock_t *socket, int how)
{
    microtcp_header_t hdr, recv_hdr;
    ssize_t n;
    struct sockaddr_storage peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    uint32_t fin_seq, fin_ack;
    struct timeval timeout;
    int retries = 0;
    const int MAX_RETRIES = 5;

    if (!socket || socket->sd < 0) {
        fprintf(stderr, "[microtcp_shutdown] Invalid socket\n");
        return -1;
    }
    
    // Αν ήδη είμαστε σε CLOSING_BY_PEER, σημαίνει ότι το recv() έλαβε FIN
    // Οπότε πρέπει να απαντήσουμε μόνο με ACK+FIN
    if (socket->state == CLOSING_BY_PEER) {
        printf("[microtcp_shutdown] Already received FIN from peer, completing shutdown...\n");
        
        // Στείλε δικό μας FIN+ACK
        memset(&hdr, 0, sizeof(hdr));
        hdr.seq_number = htonl(socket->seq_number);
        hdr.ack_number = htonl(socket->ack_number);
        hdr.control = htons((1 << 15) | (1 << 12));  // FIN=1, ACK=1
        hdr.window = htons(socket->curr_win_size);
        hdr.data_len = 0;
        hdr.future_use0 = 0;
        hdr.future_use1 = 0;
        hdr.future_use2 = 0;
        hdr.checksum = 0;
        hdr.checksum = crc32((uint8_t*)&hdr, sizeof(microtcp_header_t));
        
        sendto(socket->sd, &hdr, sizeof(hdr), 0,
               (struct sockaddr*)&socket->peer_addr, socket->peer_addr_len);
        
        socket->state = CLOSED;
        close(socket->sd);
        socket->sd = -1;
        printf("[microtcp_shutdown] Connection CLOSED\n");
        return 0;
    }

    if (socket->state != ESTABLISHED) {
        fprintf(stderr, "[microtcp_shutdown] Socket not in ESTABLISHED state\n");
        return -1;
    }

    printf("[microtcp_shutdown] Starting shutdown...\n");

    /* ==================== ΡΥΘΜΙΣΗ TIMEOUT ==================== */
    // Μεγαλύτερο timeout για shutdown (3 δευτερόλεπτα)
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("[microtcp_shutdown] setsockopt timeout failed");
    }

    /* ==================== ΒΗΜΑ 1: ΑΠΟΣΤΟΛΗ FIN ==================== */
    fin_seq = socket->seq_number;
    fin_ack = socket->ack_number;
    
    memset(&hdr, 0, sizeof(hdr));
    hdr.seq_number = htonl(fin_seq);
    hdr.ack_number = htonl(fin_ack);
    hdr.control = htons((1 << 15) | (1 << 12));  // FIN=1, ACK=1
    hdr.window = htons(socket->curr_win_size);
    hdr.data_len = 0;
    hdr.future_use0 = 0;
    hdr.future_use1 = 0;
    hdr.future_use2 = 0;
    
    hdr.checksum = 0;
    hdr.checksum = crc32((uint8_t*)&hdr, sizeof(microtcp_header_t));

    printf("[microtcp_shutdown] Sending FIN (seq=%u, ack=%u)...\n", fin_seq, fin_ack);
    
RETRY_SEND_FIN:
    n = sendto(socket->sd, &hdr, sizeof(hdr), 0,
               (struct sockaddr*)&socket->peer_addr, socket->peer_addr_len);
    
    if (n != sizeof(hdr)) {
        perror("[microtcp_shutdown] Failed to send FIN");
        return -1;
    }
    
    socket->state = CLOSING_BY_HOST;
    printf("[microtcp_shutdown] FIN sent, state -> CLOSING_BY_HOST\n");

    /* ==================== ΒΗΜΑ 2: ΛΗΨΗ ACK ==================== */
    n = recvfrom(socket->sd, &recv_hdr, sizeof(recv_hdr), 0,
                 (struct sockaddr*)&peer_addr, &peer_len);
    
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            retries++;
            if (retries < MAX_RETRIES) {
                printf("[microtcp_shutdown] Timeout waiting for ACK, retrying (%d/%d)...\n",
                       retries, MAX_RETRIES);
                goto RETRY_SEND_FIN;
            }
            fprintf(stderr, "[microtcp_shutdown] Max retries reached, giving up\n");
            return -1;
        }
        perror("[microtcp_shutdown] recv ACK failed");
        return -1;
    }

    // Checksum έλεγχος
    uint32_t recv_crc = recv_hdr.checksum;
    recv_hdr.checksum = 0;
    uint32_t calc_crc = crc32((uint8_t*)&recv_hdr, sizeof(microtcp_header_t));
    if (recv_crc != calc_crc) {
        printf("[microtcp_shutdown] Warning: ACK has bad checksum\n");
    }

    // Έλεγχος ACK flag
    uint16_t ctrl = ntohs(recv_hdr.control);
    if (!(ctrl & (1 << 12))) {
        fprintf(stderr, "[microtcp_shutdown] Expected ACK packet\n");
        return -1;
    }

    // Έλεγχος ACK number
    uint32_t recv_ack = ntohl(recv_hdr.ack_number);
    if (recv_ack != fin_seq + 1) {
        printf("[microtcp_shutdown] Warning: ACK number mismatch (got %u, expected %u)\n",
               recv_ack, fin_seq + 1);
    }

    printf("[microtcp_shutdown] Received ACK for FIN\n");
    socket->state = CLOSING_BY_PEER;

    /* ==================== ΒΗΜΑ 3: ΛΗΨΗ FIN ΑΠΟ SERVER ==================== */
    printf("[microtcp_shutdown] Waiting for server's FIN...\n");
    
    retries = 0;
RETRY_RECV_FIN:
    n = recvfrom(socket->sd, &recv_hdr, sizeof(recv_hdr), 0, NULL, NULL);
    
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            retries++;
            if (retries < MAX_RETRIES) {
                printf("[microtcp_shutdown] Timeout waiting for server FIN, retrying (%d/%d)...\n",
                       retries, MAX_RETRIES);
                goto RETRY_RECV_FIN;
            }
            fprintf(stderr, "[microtcp_shutdown] Max retries reached waiting for server FIN\n");
            // Κλείσε ούτως ή άλλως
            socket->state = CLOSED;
            close(socket->sd);
            socket->sd = -1;
            printf("[microtcp_shutdown] Connection CLOSED (timeout)\n");
            return 0;  // Return 0 γιατί κάναμε την δουλειά μας
        }
        perror("[microtcp_shutdown] recv server FIN failed");
        return -1;
    }

    // Checksum έλεγχος
    recv_crc = recv_hdr.checksum;
    recv_hdr.checksum = 0;
    calc_crc = crc32((uint8_t*)&recv_hdr, sizeof(microtcp_header_t));
    if (recv_crc != calc_crc) {
        printf("[microtcp_shutdown] Warning: FIN has bad checksum\n");
    }

    // Έλεγχος FIN flag
    ctrl = ntohs(recv_hdr.control);
    if (!(ctrl & (1 << 15))) {
        fprintf(stderr, "[microtcp_shutdown] Expected FIN packet\n");
        // Μπορεί να είναι duplicate ACK, δοκίμασε ξανά
        retries++;
        if (retries < MAX_RETRIES) {
            printf("[microtcp_shutdown] Not a FIN, retrying...\n");
            goto RETRY_RECV_FIN;
        }
        return -1;
    }

    uint32_t server_fin_seq = ntohl(recv_hdr.seq_number);
    printf("[microtcp_shutdown] Received FIN from server (seq=%u)\n", server_fin_seq);

    /* ==================== ΒΗΜΑ 4: ΑΠΟΣΤΟΛΗ ΤΕΛΙΚΟΥ ACK ==================== */
    memset(&hdr, 0, sizeof(hdr));
    hdr.seq_number = htonl(fin_seq + 1);
    hdr.ack_number = htonl(server_fin_seq + 1);
    hdr.control = htons(1 << 12);  // ACK=1
    hdr.window = htons(socket->curr_win_size);
    hdr.data_len = 0;
    hdr.future_use0 = 0;
    hdr.future_use1 = 0;
    hdr.future_use2 = 0;
    
    hdr.checksum = 0;
    hdr.checksum = crc32((uint8_t*)&hdr, sizeof(microtcp_header_t));

    printf("[microtcp_shutdown] Sending final ACK...\n");
    
    n = sendto(socket->sd, &hdr, sizeof(hdr), 0,
               (struct sockaddr*)&socket->peer_addr, socket->peer_addr_len);
    
    if (n != sizeof(hdr)) {
        perror("[microtcp_shutdown] Failed to send final ACK");
        // Συνέχισε ούτως ή άλλως
    }

    /* ==================== ΒΗΜΑ 5: ΚΛΕΙΣΙΜΟ ΣΥΝΔΕΣΗΣ ==================== */
    socket->state = CLOSED;
    close(socket->sd);
    socket->sd = -1;
    
    printf("[microtcp_shutdown] ========================================\n");
    printf("[microtcp_shutdown] CONNECTION CLOSED SUCCESSFULLY\n");
    printf("[microtcp_shutdown] ========================================\n\n");

    return 0;
}

ssize_t
microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length, int flags)
{
    microtcp_header_t *hdr_ptr;
    microtcp_header_t ack_hdr;
    uint8_t *packet;
    ssize_t n;
    size_t remaining, data_sent, bytes_to_send, chunk_size;
    size_t chunks, i;
    const uint8_t *data_ptr;
    uint32_t effective_window;
    struct timeval timeout;
    int retransmit_count;
    size_t packet_size;
    
    /* ==================== ΒΗΜΑ 1: ΕΛΕΓΧΟΙ ΕΓΚΥΡΟΤΗΤΑΣ ==================== */
    if (!socket || !buffer || length == 0) {
        fprintf(stderr, "[microtcp_send] Invalid parameters\n");
        return -1;
    }
    
    if (socket->state != ESTABLISHED) {
        fprintf(stderr, "[microtcp_send] Socket not in ESTABLISHED state\n");
        return -1;
    }
    
    printf("[microtcp_send] Starting transmission: %zu bytes\n", length);
    
    /* ==================== ΒΗΜΑ 2: ΡΥΘΜΙΣΗ TIMEOUT ==================== */
    timeout.tv_sec = 0;
    timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;
    if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("[microtcp_send] setsockopt failed");
        return -1;
    }
    
    /* ==================== ΒΗΜΑ 3: ΑΡΧΙΚΟΠΟΙΗΣΗ ΜΕΤΑΒΛΗΤΩΝ ==================== */
    remaining = length;
    data_sent = 0;
    data_ptr = (const uint8_t*)buffer;
    
    /* ==================== ΒΗΜΑ 4: ΚΥΡΙΟΣ ΒΡΟΧΟΣ ΑΠΟΣΤΟΛΗΣ ==================== */
    while (data_sent < length) {
        
        /* --------- 4.1: ΥΠΟΛΟΓΙΣΜΟΣ EFFECTIVE WINDOW --------- */
        effective_window = (socket->peer_win_size < socket->cwnd) ? 
                          socket->peer_win_size : socket->cwnd;
        
        bytes_to_send = (effective_window < remaining) ? effective_window : remaining;
        
        /* --------- 4.2: WINDOW PROBE (αν window = 0) --------- */
        if (bytes_to_send == 0) {
            printf("[microtcp_send] Window is 0, sending window probe...\n");
            
            usleep(rand() % MICROTCP_ACK_TIMEOUT_US);
            
            // Δημιουργία probe packet (χωρίς data)
            packet = malloc(sizeof(microtcp_header_t));
            hdr_ptr = (microtcp_header_t*)packet;
            
            memset(hdr_ptr, 0, sizeof(microtcp_header_t));
            hdr_ptr->seq_number = htonl(socket->seq_number);
            hdr_ptr->ack_number = htonl(socket->ack_number);
            hdr_ptr->control = htons(1 << 12);  // ACK=1
            hdr_ptr->window = htons(socket->curr_win_size);
            hdr_ptr->data_len = 0;
            hdr_ptr->future_use0 = 0;
            hdr_ptr->future_use1 = 0;
            hdr_ptr->future_use2 = 0;
            hdr_ptr->checksum = 0;
            hdr_ptr->checksum = crc32((uint8_t*)hdr_ptr, sizeof(microtcp_header_t));
            
            sendto(socket->sd, packet, sizeof(microtcp_header_t), 0,
                   (struct sockaddr*)&socket->peer_addr, socket->peer_addr_len);
            free(packet);
            
            // Λήψη ACK
            n = recvfrom(socket->sd, &ack_hdr, sizeof(ack_hdr), 0, NULL, NULL);
            if (n > 0) {
                socket->peer_win_size = ntohs(ack_hdr.window);
                printf("[microtcp_send] Window updated: %zu bytes\n", socket->peer_win_size);
            }
            continue;
        }
        
        /* --------- 4.3: ΚΑΤΑΚΕΡΜΑΤΙΣΜΟΣ ΣΕ CHUNKS --------- */
        chunks = bytes_to_send / MICROTCP_MSS;
        if (bytes_to_send % MICROTCP_MSS) {
            chunks++;
        }
        
        printf("[microtcp_send] Sending %zu bytes in %zu chunks (window: flow=%zu, cwnd=%zu)\n",
               bytes_to_send, chunks, socket->peer_win_size, socket->cwnd);
        
        /* --------- 4.4: ΑΠΟΣΤΟΛΗ CHUNKS --------- */
        for (i = 0; i < chunks; i++) {
            // Υπολογισμός μεγέθους chunk
            size_t offset = data_sent + (i * MICROTCP_MSS);
            chunk_size = MICROTCP_MSS;
            if (offset + chunk_size > length) {
                chunk_size = length - offset;
            }
            
            retransmit_count = 0;
            
RETRANSMIT_CHUNK:
            // Δημιουργία ενιαίου packet (header + data)
            packet_size = sizeof(microtcp_header_t) + chunk_size;
            packet = malloc(packet_size);
            if (!packet) {
                perror("[microtcp_send] malloc failed");
                return -1;
            }
            
            hdr_ptr = (microtcp_header_t*)packet;
            
            // Δημιουργία header
            memset(hdr_ptr, 0, sizeof(microtcp_header_t));
            hdr_ptr->seq_number = htonl(socket->seq_number);
            hdr_ptr->ack_number = htonl(socket->ack_number);
            hdr_ptr->control = htons(1 << 12);  // ACK=1
            hdr_ptr->window = htons(socket->curr_win_size);
            hdr_ptr->data_len = htonl(chunk_size);
            hdr_ptr->future_use0 = 0;
            hdr_ptr->future_use1 = 0;
            hdr_ptr->future_use2 = 0;
            
            // Αντιγραφή data
            memcpy(packet + sizeof(microtcp_header_t), data_ptr + offset, chunk_size);
            
            // Υπολογισμός checksum για ολόκληρο το πακέτο
            hdr_ptr->checksum = 0;
            hdr_ptr->checksum = crc32(packet, packet_size);
            
            printf("[microtcp_send] Sending chunk %zu/%zu: seq=%u, len=%zu\n",
                   i + 1, chunks, socket->seq_number, chunk_size);
            
            // Αποστολή ολόκληρου του πακέτου με ΜΙΑ κλήση
            n = sendto(socket->sd, packet, packet_size, 0,
                      (struct sockaddr*)&socket->peer_addr, socket->peer_addr_len);
            
            free(packet);
            
            if (n != packet_size) {
                perror("[microtcp_send] sendto failed");
                return -1;
            }
            
            socket->packets_send++;
            socket->bytes_send += packet_size;
            
            /* --------- 4.5: ΛΗΨΗ ACK --------- */
            n = recvfrom(socket->sd, &ack_hdr, sizeof(ack_hdr), 0, NULL, NULL);
            
            // Έλεγχος timeout
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    printf("[microtcp_send] Timeout waiting for ACK, retransmitting...\n");
                    socket->packets_lost++;
                    
                    // Congestion control: timeout
                    socket->ssthresh = socket->cwnd / 2;
                    socket->cwnd = (MICROTCP_MSS < socket->ssthresh) ? 
                                   MICROTCP_MSS : socket->ssthresh;
                    socket->cc_state = 0;  // SLOW_START
                    
                    printf("[microtcp_send] Timeout: ssthresh=%zu, cwnd=%zu\n",
                           socket->ssthresh, socket->cwnd);
                    
                    retransmit_count++;
                    if (retransmit_count > 5) {
                        fprintf(stderr, "[microtcp_send] Too many retransmissions\n");
                        return -1;
                    }
                    goto RETRANSMIT_CHUNK;
                }
                perror("[microtcp_send] recvfrom failed");
                return -1;
            }
            
            socket->packets_received++;
            socket->bytes_received += n;
            
            /* --------- 4.6: ΕΛΕΓΧΟΣ CHECKSUM ACK --------- */
            uint32_t recv_crc = ack_hdr.checksum;
            ack_hdr.checksum = 0;
            uint32_t calc_crc = crc32((uint8_t*)&ack_hdr, sizeof(microtcp_header_t));
            
            if (recv_crc != calc_crc) {
                printf("[microtcp_send] ACK checksum mismatch, retransmitting...\n");
                socket->packets_lost++;
                retransmit_count++;
                if (retransmit_count > 5) {
                    fprintf(stderr, "[microtcp_send] Too many retransmissions\n");
                    return -1;
                }
                goto RETRANSMIT_CHUNK;
            }
            
            /* --------- 4.7: ΕΛΕΓΧΟΣ ACK NUMBER --------- */
            uint32_t recv_ack = ntohl(ack_hdr.ack_number);
            uint32_t expected_ack = socket->seq_number + chunk_size;
            
            // Έλεγχος για duplicate ACK
            if (recv_ack == socket->last_ack_received) {
                socket->dup_ack_count++;
                printf("[microtcp_send] Duplicate ACK received (%u), count=%u\n",
                       recv_ack, socket->dup_ack_count);
                
                // Fast retransmit: 3 duplicate ACKs
                if (socket->dup_ack_count >= 3) {
                    printf("[microtcp_send] 3 duplicate ACKs, fast retransmit!\n");
                    
                    // Congestion control: fast retransmit
                    socket->ssthresh = socket->cwnd / 2;
                    socket->cwnd = socket->cwnd / 2 + 1;
                    socket->cc_state = 1;  // CONGESTION_AVOIDANCE
                    
                    printf("[microtcp_send] Fast retransmit: ssthresh=%zu, cwnd=%zu\n",
                           socket->ssthresh, socket->cwnd);
                    
                    socket->dup_ack_count = 0;
                    socket->packets_lost++;
                    retransmit_count++;
                    if (retransmit_count > 5) {
                        fprintf(stderr, "[microtcp_send] Too many retransmissions\n");
                        return -1;
                    }
                    goto RETRANSMIT_CHUNK;
                }
                
                retransmit_count++;
                if (retransmit_count > 5) {
                    fprintf(stderr, "[microtcp_send] Too many retransmissions\n");
                    return -1;
                }
                goto RETRANSMIT_CHUNK;
            }
            
            // Νέο ACK (όχι duplicate)
            if (recv_ack != expected_ack) {
                fprintf(stderr, "[microtcp_send] Unexpected ACK: got %u, expected %u\n",
                       recv_ack, expected_ack);
                retransmit_count++;
                if (retransmit_count > 5) {
                    return -1;
                }
                goto RETRANSMIT_CHUNK;
            }
            
            // ACK σωστό!
            socket->last_ack_received = recv_ack;
            socket->dup_ack_count = 0;
            
            /* --------- 4.8: ΕΝΗΜΕΡΩΣΗ PEER WINDOW --------- */
            socket->peer_win_size = ntohs(ack_hdr.window);
            
            /* --------- 4.9: ΕΝΗΜΕΡΩΣΗ SEQUENCE NUMBER --------- */
            socket->seq_number += chunk_size;
            
            /* --------- 4.10: CONGESTION CONTROL --------- */
            if (socket->cc_state == 0) {
                // SLOW START: cwnd += MSS για κάθε ACK
                socket->cwnd += MICROTCP_MSS;
                
                if (socket->cwnd > socket->ssthresh) {
                    socket->cc_state = 1;
                    printf("[microtcp_send] Switched to CONGESTION_AVOIDANCE\n");
                }
            } else {
                // CONGESTION AVOIDANCE: cwnd += MSS * MSS / cwnd
                socket->cwnd += (MICROTCP_MSS * MICROTCP_MSS) / socket->cwnd;
            }
            
            printf("[microtcp_send] ACK OK: ack=%u, peer_win=%zu, cwnd=%zu (state=%s)\n",
                   recv_ack, socket->peer_win_size, socket->cwnd,
                   socket->cc_state == 0 ? "SLOW_START" : "CONG_AVOID");
        }
        
        /* --------- 4.11: ΕΝΗΜΕΡΩΣΗ ΠΡΟΟΔΟΥ --------- */
        data_sent += bytes_to_send;
        remaining -= bytes_to_send;
        
        printf("[microtcp_send] Progress: %zu/%zu bytes sent\n", data_sent, length);
    }
    
    /* ==================== ΒΗΜΑ 5: ΟΛΟΚΛΗΡΩΣΗ ==================== */
    printf("[microtcp_send] ========================================\n");
    printf("[microtcp_send] TRANSMISSION COMPLETED SUCCESSFULLY\n");
    printf("[microtcp_send] Total bytes sent: %zu\n", data_sent);
    printf("[microtcp_send] Packets sent: %lu, received: %lu, lost: %lu\n",
           socket->packets_send, socket->packets_received, socket->packets_lost);
    printf("[microtcp_send] Final cwnd: %zu, ssthresh: %zu\n",
           socket->cwnd, socket->ssthresh);
    printf("[microtcp_send] ========================================\n\n");
    
    return data_sent;
}

ssize_t
microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
    microtcp_header_t *hdr_ptr;
    microtcp_header_t ack_hdr;
    uint8_t *packet;
    ssize_t n;
    size_t total_received, bytes_to_read, data_len;
    uint8_t *buffer_ptr;
    uint32_t recv_seq, expected_seq;
    uint16_t ctrl;
    size_t max_packet_size;
    
    /* ==================== ΒΗΜΑ 1: ΕΛΕΓΧΟΙ ΕΓΚΥΡΟΤΗΤΑΣ ==================== */
    if (!socket || !buffer || length == 0) {
        fprintf(stderr, "[microtcp_recv] Invalid parameters\n");
        return -1;
    }
    
    if (socket->state != ESTABLISHED) {
        fprintf(stderr, "[microtcp_recv] Socket not in ESTABLISHED state\n");
        return -1;
    }
    
    printf("[microtcp_recv] Waiting to receive up to %zu bytes\n", length);
    
    /* ==================== ΒΗΜΑ 2: ΑΡΧΙΚΟΠΟΙΗΣΗ ΜΕΤΑΒΛΗΤΩΝ ==================== */
    total_received = 0;
    buffer_ptr = (uint8_t*)buffer;
    max_packet_size = sizeof(microtcp_header_t) + MICROTCP_MSS;
    
    packet = malloc(max_packet_size);
    if (!packet) {
        perror("[microtcp_recv] malloc failed");
        return -1;
    }
    
    /* ==================== ΒΗΜΑ 3: ΚΥΡΙΟΣ ΒΡΟΧΟΣ ΛΗΨΗΣ ==================== */
    while (total_received < length) {
        
        /* --------- 3.1: ΛΗΨΗ ΠΑΚΕΤΟΥ (header + data μαζί) --------- */
        memset(packet, 0, max_packet_size);
        n = recvfrom(socket->sd, packet, max_packet_size, 0, NULL, NULL);
        
        if (n < 0) {
            perror("[microtcp_recv] Failed to receive packet");
            free(packet);
            return -1;
        }
        
        if (n < sizeof(microtcp_header_t)) {
            fprintf(stderr, "[microtcp_recv] Incomplete packet received\n");
            continue;
        }
        
        socket->packets_received++;
        socket->bytes_received += n;
        
        /* --------- 3.2: EXTRACT HEADER --------- */
        hdr_ptr = (microtcp_header_t*)packet;
        
        /* --------- 3.3: ΕΛΕΓΧΟΣ CONTROL FLAGS --------- */
        ctrl = ntohs(hdr_ptr->control);
        
        // Έλεγχος για FIN (τερματισμός σύνδεσης)
        if (ctrl & (1 << 15)) {
            printf("[microtcp_recv] Received FIN, connection closing by peer\n");
            socket->state = CLOSING_BY_PEER;
            
            // Αποστολή ACK για το FIN
            memset(&ack_hdr, 0, sizeof(ack_hdr));
            ack_hdr.seq_number = htonl(socket->seq_number);
            ack_hdr.ack_number = htonl(ntohl(hdr_ptr->seq_number) + 1);
            ack_hdr.control = htons(1 << 12);  // ACK=1
            ack_hdr.window = htons(socket->curr_win_size);
            ack_hdr.data_len = 0;
            ack_hdr.future_use0 = 0;
            ack_hdr.future_use1 = 0;
            ack_hdr.future_use2 = 0;
            ack_hdr.checksum = 0;
            ack_hdr.checksum = crc32((uint8_t*)&ack_hdr, sizeof(microtcp_header_t));
            
            sendto(socket->sd, &ack_hdr, sizeof(ack_hdr), 0,
                   (struct sockaddr*)&socket->peer_addr, socket->peer_addr_len);
            
            free(packet);
            return total_received;

        }
        
        /* --------- 3.4: EXTRACT DATA LENGTH --------- */
        data_len = ntohl(hdr_ptr->data_len);
        
        // Έλεγχος ότι το πακέτο έχει το σωστό μέγεθος
        if (n != sizeof(microtcp_header_t) + data_len) {
            fprintf(stderr, "[microtcp_recv] Packet size mismatch\n");
            goto SEND_DUPLICATE_ACK;
        }
        
        if (data_len > MICROTCP_MSS) {
            fprintf(stderr, "[microtcp_recv] Data length exceeds MSS\n");
            goto SEND_DUPLICATE_ACK;
        }
        
        /* --------- 3.5: ΕΛΕΓΧΟΣ CHECKSUM --------- */
        uint32_t recv_crc = hdr_ptr->checksum;
        hdr_ptr->checksum = 0;
        uint32_t calc_crc = crc32(packet, sizeof(microtcp_header_t) + data_len);
        
        if (recv_crc != calc_crc) {
            fprintf(stderr, "[microtcp_recv] CHECKSUM MISMATCH - dropping packet\n");
            fprintf(stderr, "[microtcp_recv] Received: 0x%08X, Calculated: 0x%08X\n",
                   recv_crc, calc_crc);
            goto SEND_DUPLICATE_ACK;
        }
        
        printf("[microtcp_recv] Checksum OK (0x%08X)\n", recv_crc);
        
        /* --------- 3.6: ΕΛΕΓΧΟΣ SEQUENCE NUMBER --------- */
        recv_seq = ntohl(hdr_ptr->seq_number);
        expected_seq = socket->ack_number;
        
        if (recv_seq != expected_seq) {
            fprintf(stderr, "[microtcp_recv] Out-of-order packet\n");
            fprintf(stderr, "[microtcp_recv] Got seq=%u, Expected seq=%u\n",
                   recv_seq, expected_seq);
            goto SEND_DUPLICATE_ACK;
        }
        
        printf("[microtcp_recv] Received packet: seq=%u, len=%u\n", recv_seq, data_len);
        
        /* --------- 3.7: ΑΠΟΘΗΚΕΥΣΗ ΔΕΔΟΜΕΝΩΝ --------- */
        if (data_len > 0) {
            // Έλεγχος αν χωράει στον receive buffer
            if (socket->buf_fill_level + data_len > MICROTCP_RECVBUF_LEN) {
                fprintf(stderr, "[microtcp_recv] Receive buffer overflow\n");
                goto SEND_DUPLICATE_ACK;
            }
            
            // Αποθήκευση στον receive buffer
            memcpy(socket->recvbuf + socket->buf_fill_level, 
                   packet + sizeof(microtcp_header_t), data_len);
            socket->buf_fill_level += data_len;
            
            // Ενημέρωση current window (μείωση διαθέσιμου χώρου)
            socket->curr_win_size = MICROTCP_RECVBUF_LEN - socket->buf_fill_level;
            
            // Ενημέρωση ACK number για το επόμενο αναμενόμενο sequence
            socket->ack_number = recv_seq + data_len;
            
            printf("[microtcp_recv] Data stored in buffer: fill_level=%zu, curr_win=%zu\n",
                   socket->buf_fill_level, socket->curr_win_size);
        }
        
        /* --------- 3.8: ΑΠΟΣΤΟΛΗ ACK --------- */
        memset(&ack_hdr, 0, sizeof(ack_hdr));
        ack_hdr.seq_number = htonl(socket->seq_number);
        ack_hdr.ack_number = htonl(socket->ack_number);
        ack_hdr.control = htons(1 << 12);  // ACK=1
        ack_hdr.window = htons(socket->curr_win_size);
        ack_hdr.data_len = 0;
        ack_hdr.future_use0 = 0;
        ack_hdr.future_use1 = 0;
        ack_hdr.future_use2 = 0;
        
        ack_hdr.checksum = 0;
        ack_hdr.checksum = crc32((uint8_t*)&ack_hdr, sizeof(microtcp_header_t));
        
        n = sendto(socket->sd, &ack_hdr, sizeof(ack_hdr), 0,
                   (struct sockaddr*)&socket->peer_addr, socket->peer_addr_len);
        
        if (n != sizeof(ack_hdr)) {
            perror("[microtcp_recv] Failed to send ACK");
            free(packet);
            return -1;
        }
        
        socket->packets_send++;
        socket->bytes_send += sizeof(ack_hdr);
        
        printf("[microtcp_recv] ACK sent: ack=%u, window=%zu\n",
               socket->ack_number, socket->curr_win_size);
        
        /* --------- 3.9: ΠΡΟΩΘΗΣΗ ΔΕΔΟΜΕΝΩΝ ΣΤΟΝ ΧΡΗΣΤΗ --------- */
        bytes_to_read = (socket->buf_fill_level < (length - total_received)) ?
                        socket->buf_fill_level : (length - total_received);
        
        if (bytes_to_read > 0) {
            memcpy(buffer_ptr, socket->recvbuf, bytes_to_read);
            
            // Μετακίνηση υπολοίπων δεδομένων στην αρχή του buffer
            if (bytes_to_read < socket->buf_fill_level) {
                memmove(socket->recvbuf, socket->recvbuf + bytes_to_read,
                       socket->buf_fill_level - bytes_to_read);
            }
            
            socket->buf_fill_level -= bytes_to_read;
            socket->curr_win_size = MICROTCP_RECVBUF_LEN - socket->buf_fill_level;
            
            total_received += bytes_to_read;
            buffer_ptr += bytes_to_read;
            
            printf("[microtcp_recv] Forwarded %zu bytes to user (total: %zu/%zu)\n",
                   bytes_to_read, total_received, length);
        }
        
        // Αν έχουμε λάβει όσα ζήτησε ο χρήστης, τερματισμός
        if (total_received >= length) {
            break;
        }
        
        continue;
        
SEND_DUPLICATE_ACK:
        /* --------- 3.10: ΑΠΟΣΤΟΛΗ DUPLICATE ACK --------- */
        printf("[microtcp_recv] Sending duplicate ACK\n");
        
        memset(&ack_hdr, 0, sizeof(ack_hdr));
        ack_hdr.seq_number = htonl(socket->seq_number);
        ack_hdr.ack_number = htonl(socket->ack_number);  // Το ίδιο ACK
        ack_hdr.control = htons(1 << 12);  // ACK=1
        ack_hdr.window = htons(socket->curr_win_size);
        ack_hdr.data_len = 0;
        ack_hdr.future_use0 = 0;
        ack_hdr.future_use1 = 0;
        ack_hdr.future_use2 = 0;
        
        ack_hdr.checksum = 0;
        ack_hdr.checksum = crc32((uint8_t*)&ack_hdr, sizeof(microtcp_header_t));
        
        sendto(socket->sd, &ack_hdr, sizeof(ack_hdr), 0,
               (struct sockaddr*)&socket->peer_addr, socket->peer_addr_len);
        
        socket->packets_send++;
        socket->bytes_send += sizeof(ack_hdr);
    }
    
    /* ==================== ΒΗΜΑ 4: ΟΛΟΚΛΗΡΩΣΗ ==================== */
    free(packet);
    
    printf("[microtcp_recv] ========================================\n");
    printf("[microtcp_recv] RECEPTION COMPLETED SUCCESSFULLY\n");
    printf("[microtcp_recv] Total bytes received: %zu\n", total_received);
    printf("[microtcp_recv] Buffer fill level: %zu, Current window: %zu\n",
           socket->buf_fill_level, socket->curr_win_size);
    printf("[microtcp_recv] Packets sent: %lu, received: %lu\n",
           socket->packets_send, socket->packets_received);
    printf("[microtcp_recv] ========================================\n\n");
    
    return total_received;
}