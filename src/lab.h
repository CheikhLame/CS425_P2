#ifndef LAB_H
#define LAB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PACKET_TYPE_DATA 0u
#define PACKET_TYPE_ACK 1u
#define PACKET_TYPE_FIN 2u
#define PACKET_HEADER_SIZE 10u
#define PACKET_MAX_PAYLOAD 1024u
#define PACKET_MAX_SIZE (PACKET_HEADER_SIZE + PACKET_MAX_PAYLOAD)
#define FILE_CHUNK_SIZE 1024u
#define INVALID_SEQ UINT32_MAX

typedef struct {
    uint8_t type;
    uint8_t reserved;
    uint16_t checksum;
    uint32_t seq;
    uint16_t length;
    uint8_t payload[PACKET_MAX_PAYLOAD];
} Packet;

typedef struct {
    uint32_t base;
    uint32_t next;
    uint32_t window;
    uint32_t timeout_ms;
    uint32_t total_packets;
    const uint8_t *file_data;
    size_t file_size;
    Packet *copy;
    uint32_t timeout_count;
    bool timer_running;
    bool fin_sent;
    bool done;
} SenderState;

typedef struct {
    uint32_t expected;
    bool finished;
    bool should_linger;
    uint32_t last_ack;
} ReceiverState;

typedef struct {
    bool valid;
    uint32_t ack_seq;
    uint32_t seq;
    uint8_t type;
    uint16_t length;
    uint8_t payload[PACKET_MAX_PAYLOAD];
    bool has_payload;
} ReceiverEvent;

uint16_t packet_checksum(const uint8_t *data, size_t length);
bool packet_encode(const Packet *packet, uint8_t *buffer, size_t buffer_size, size_t *written);
bool packet_decode(const uint8_t *buffer, size_t length, Packet *packet);

void sender_init(SenderState *state, uint32_t window, uint32_t timeout_ms);
void sender_set_file(SenderState *state, const uint8_t *file_data, size_t file_size);
void sender_release(SenderState *state);
size_t sender_ready_packets(SenderState *state, Packet *out, size_t max_packets);
void sender_on_ack(SenderState *state, uint32_t ack_seq);
size_t sender_on_timeout(SenderState *state, Packet *out, size_t max_packets);

void receiver_init(ReceiverState *state);
bool receiver_on_packet(ReceiverState *state, const Packet *packet,
                       uint32_t *ack_seq, uint8_t *out_payload,
                       size_t *out_length, bool *delivered);

#endif
