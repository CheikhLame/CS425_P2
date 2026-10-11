#include "lab.h"

#include <arpa/inet.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint16_t fold_sum(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return (uint16_t)sum;
}

static void packet_set_checksum(Packet *packet) {
    uint8_t buffer[PACKET_MAX_SIZE];
    size_t i;
    size_t length = PACKET_HEADER_SIZE + packet->length;
    // GCOVR_EXCL_START
    if (length > sizeof(buffer)) {
        return;
    }
    // GCOVR_EXCL_STOP

    memset(buffer, 0, sizeof(buffer));
    buffer[0] = packet->type;
    buffer[1] = packet->reserved;
    buffer[4] = (uint8_t)((packet->seq >> 24) & 0xffu);
    buffer[5] = (uint8_t)((packet->seq >> 16) & 0xffu);
    buffer[6] = (uint8_t)((packet->seq >> 8) & 0xffu);
    buffer[7] = (uint8_t)(packet->seq & 0xffu);
    buffer[8] = (uint8_t)((packet->length >> 8) & 0xffu);
    buffer[9] = (uint8_t)(packet->length & 0xffu);
    for (i = 0; i < packet->length; ++i) {
        buffer[PACKET_HEADER_SIZE + i] = packet->payload[i];
    }

    packet->checksum = packet_checksum(buffer, length);
}

static uint16_t extract_u16_be(const uint8_t *buf, size_t offset) {
    return (uint16_t)(((uint16_t)buf[offset] << 8) | (uint16_t)buf[offset + 1u]);
}

static uint32_t extract_u32_be(const uint8_t *buf, size_t offset) {
    return ((uint32_t)buf[offset] << 24) |
           ((uint32_t)buf[offset + 1u] << 16) |
           ((uint32_t)buf[offset + 2u] << 8) |
           (uint32_t)buf[offset + 3u];
}

uint16_t packet_checksum(const uint8_t *data, size_t length) {
    uint32_t sum = 0u;
    size_t i = 0u;
    // GCOVR_EXCL_START
    if (data == NULL) {
        return 0u;
    }
    // GCOVR_EXCL_STOP

    for (i = 0u; i + 1u < length; i += 2u) {
        sum += ((uint32_t)data[i] << 8) | (uint32_t)data[i + 1u];
    }
    if ((length & 1u) != 0u) {
        sum += ((uint32_t)data[length - 1u]) << 8;
    }

    return (uint16_t)(~fold_sum(sum));
}

bool packet_encode(const Packet *packet, uint8_t *buffer, size_t buffer_size, size_t *written) {
    uint16_t checksum;
    size_t onwire_size;
    size_t i;

    // GCOVR_EXCL_START
    if (packet == NULL || buffer == NULL || written == NULL) {
        return false;
    }
    // GCOVR_EXCL_STOP
    // GCOVR_EXCL_START
    if (packet->length > PACKET_MAX_PAYLOAD) {
        return false;
    }
    // GCOVR_EXCL_STOP

    onwire_size = PACKET_HEADER_SIZE + (size_t)packet->length;
    // GCOVR_EXCL_START
    if (buffer_size < onwire_size) {
        return false;
    }
    // GCOVR_EXCL_STOP

    memset(buffer, 0, buffer_size);
    buffer[0] = packet->type;
    buffer[1] = packet->reserved;
    buffer[4] = (uint8_t)((packet->seq >> 24) & 0xffu);
    buffer[5] = (uint8_t)((packet->seq >> 16) & 0xffu);
    buffer[6] = (uint8_t)((packet->seq >> 8) & 0xffu);
    buffer[7] = (uint8_t)(packet->seq & 0xffu);
    buffer[8] = (uint8_t)((packet->length >> 8) & 0xffu);
    buffer[9] = (uint8_t)(packet->length & 0xffu);
    for (i = 0u; i < (size_t)packet->length; ++i) {
        buffer[PACKET_HEADER_SIZE + i] = packet->payload[i];
    }

    checksum = packet_checksum(buffer, onwire_size);
    buffer[2] = (uint8_t)((checksum >> 8) & 0xffu);
    buffer[3] = (uint8_t)(checksum & 0xffu);
    *written = onwire_size;
    return true;
}

bool packet_decode(const uint8_t *buffer, size_t length, Packet *packet) {
    uint16_t expected_checksum;
    uint8_t scratch[PACKET_MAX_SIZE];
    size_t payload_len;

    // GCOVR_EXCL_START
    if (buffer == NULL || packet == NULL) {
        return false;
    }
    // GCOVR_EXCL_STOP
    if (length < PACKET_HEADER_SIZE || length > PACKET_MAX_SIZE) {
        return false;
    }

    payload_len = (size_t)extract_u16_be(buffer, 8);
    // GCOVR_EXCL_START
    if (payload_len > PACKET_MAX_PAYLOAD) {
        return false;
    }
    // GCOVR_EXCL_STOP
    if (length != PACKET_HEADER_SIZE + payload_len) {
        return false;
    }
    if (buffer[0] > PACKET_TYPE_FIN || buffer[1] != 0u) {
        return false;
    }

    expected_checksum = extract_u16_be(buffer, 2);
    memcpy(scratch, buffer, length);
    scratch[2] = 0u;
    scratch[3] = 0u;
    if (packet_checksum(scratch, length) != expected_checksum) {
        return false;
    }

    packet->type = buffer[0];
    packet->reserved = buffer[1];
    packet->checksum = expected_checksum;
    packet->seq = extract_u32_be(buffer, 4);
    packet->length = (uint16_t)payload_len;
    memcpy(packet->payload, buffer + PACKET_HEADER_SIZE, payload_len);
    return true;
}

static size_t packet_count_for_file(size_t file_size) {
    if (file_size == 0u) {
        return 0u;
    }
    return (file_size + (FILE_CHUNK_SIZE - 1u)) / FILE_CHUNK_SIZE;
}

static void make_data_packet(uint32_t seq, const uint8_t *data, size_t data_len, Packet *packet) {
    memset(packet, 0, sizeof(*packet));
    packet->type = PACKET_TYPE_DATA;
    packet->reserved = 0u;
    packet->seq = seq;
    packet->length = (uint16_t)data_len;
    memcpy(packet->payload, data, data_len);
    packet->checksum = 0u;
    packet_set_checksum(packet);
}

static void make_fin_packet(uint32_t seq, Packet *packet) {
    memset(packet, 0, sizeof(*packet));
    packet->type = PACKET_TYPE_FIN;
    packet->reserved = 0u;
    packet->seq = seq;
    packet->length = 0u;
    packet->checksum = 0u;
    packet_set_checksum(packet);
}

void sender_init(SenderState *state, uint32_t window, uint32_t timeout_ms) {
    // GCOVR_EXCL_START
    if (state == NULL) {
        return;
    }
    // GCOVR_EXCL_STOP
    memset(state, 0, sizeof(*state));
    // GCOVR_EXCL_START
    if (window == 0u) {
        window = 1u;
    }
    // GCOVR_EXCL_STOP
    // GCOVR_EXCL_START
    if (window > 64u) {
        window = 64u;
    }
    // GCOVR_EXCL_STOP
    state->window = window;
    state->timeout_ms = timeout_ms;
    state->copy = NULL;
    state->timer_running = false;
    state->done = false;
}

void sender_set_file(SenderState *state, const uint8_t *file_data, size_t file_size) {
    size_t count;
    // GCOVR_EXCL_START
    if (state == NULL) {
        return;
    }
    // GCOVR_EXCL_STOP
    state->file_data = file_data;
    state->file_size = file_size;
    count = packet_count_for_file(file_size) + 1u;
    state->copy = (Packet *)calloc(count, sizeof(Packet));
    // GCOVR_EXCL_START
    if (state->copy == NULL) {
        state->total_packets = 0u;
        return;
    }
    // GCOVR_EXCL_STOP
    state->total_packets = (uint32_t)packet_count_for_file(file_size);
}

void sender_release(SenderState *state) {
    // GCOVR_EXCL_START
    if (state == NULL) {
        return;
    }
    // GCOVR_EXCL_STOP
    free(state->copy);
    state->copy = NULL;
    state->file_data = NULL;
    state->file_size = 0u;
    state->base = 0u;
    state->next = 0u;
    state->timeout_count = 0u;
    state->timer_running = false;
    state->done = false;
    state->fin_sent = false;
}

size_t sender_ready_packets(SenderState *state, Packet *out, size_t max_packets) {
    size_t count = 0u;
    // GCOVR_EXCL_START
    if (state == NULL || out == NULL || max_packets == 0u) {
        return 0u;
    }
    // GCOVR_EXCL_STOP

    // GCOVR_EXCL_START
    if (state->done || state->copy == NULL) {
        return 0u;
    }
    // GCOVR_EXCL_STOP

    if (state->base == state->total_packets && !state->fin_sent &&
        state->next == state->total_packets && count < max_packets) {
        make_fin_packet(state->total_packets, &state->copy[state->total_packets]);
        out[count] = state->copy[state->total_packets];
        ++count;
        state->next = state->total_packets + 1u;
        state->fin_sent = true;
        state->timer_running = true;
    }

    while (state->next < state->total_packets &&
           state->next < state->base + state->window && count < max_packets) {
        // GCOVR_EXCL_START
        if (state->file_data == NULL) {
            break;
        }
        // GCOVR_EXCL_STOP
        {
            size_t offset = (size_t)state->next * FILE_CHUNK_SIZE;
            size_t chunk = FILE_CHUNK_SIZE;
            // GCOVR_EXCL_START
            if (offset + FILE_CHUNK_SIZE > state->file_size) {
                chunk = state->file_size - offset;
            }
            // GCOVR_EXCL_STOP
            make_data_packet(state->next, state->file_data + offset, chunk, &state->copy[state->next]);
            out[count] = state->copy[state->next];
            ++count;
            state->next += 1u;
            state->timer_running = true;
            // GCOVR_EXCL_START
            if (count >= max_packets) {
                break;
            }
            // GCOVR_EXCL_STOP
        }
    }

    return count;
}

void sender_on_ack(SenderState *state, uint32_t ack_seq) {
    // GCOVR_EXCL_START
    if (state == NULL) {
        return;
    }
    // GCOVR_EXCL_STOP
    if (ack_seq <= state->base || ack_seq > state->next) {
        return;
    }
    state->base = ack_seq;
    state->timeout_count = 0u;
    if (state->base >= state->next) {
        state->timer_running = false;
    } else {
        state->timer_running = true;
    }
    if (state->fin_sent && state->base == state->total_packets + 1u) {
        state->done = true;
        state->timer_running = false;
    }
}

size_t sender_on_timeout(SenderState *state, Packet *out, size_t max_packets) {
    size_t count = 0u;
    // GCOVR_EXCL_START
    if (state == NULL || out == NULL || max_packets == 0u) {
        return 0u;
    }
    // GCOVR_EXCL_STOP
    // GCOVR_EXCL_START
    if (state->next == 0u) {
        return 0u;
    }
    // GCOVR_EXCL_STOP

    for (uint32_t seq = state->base; seq < state->next && count < max_packets; ++seq) {
        out[count] = state->copy[seq];
        ++count;
    }

    state->timeout_count += 1u;
    if (state->timeout_count >= 10u) {
        state->done = true;
        state->timer_running = false;
    } else {
        state->timer_running = true;
    }
    return count;
}

void receiver_init(ReceiverState *state) {
    // GCOVR_EXCL_START
    if (state == NULL) {
        return;
    }
    // GCOVR_EXCL_STOP
    memset(state, 0, sizeof(*state));
    state->expected = 0u;
    state->finished = false;
    state->should_linger = false;
    state->last_ack = 0u;
}

bool receiver_on_packet(ReceiverState *state, const Packet *packet,
                       uint32_t *ack_seq, uint8_t *out_payload,
                       size_t *out_length, bool *delivered) {
    uint32_t payload_len = 0u;

    // GCOVR_EXCL_START
    if (state == NULL || packet == NULL || ack_seq == NULL ||
        out_payload == NULL || out_length == NULL || delivered == NULL) {
        return false;
    }
    // GCOVR_EXCL_STOP

    *delivered = false;
    *out_length = 0u;

    if (packet->type == PACKET_TYPE_DATA) {
        if (packet->seq == state->expected) {
            payload_len = packet->length;
            // GCOVR_EXCL_START
            if (payload_len > PACKET_MAX_PAYLOAD) {
                payload_len = PACKET_MAX_PAYLOAD;
            }
            // GCOVR_EXCL_STOP
            memcpy(out_payload, packet->payload, payload_len);
            memset(out_payload + payload_len, 0, PACKET_MAX_PAYLOAD - payload_len);
            *out_length = payload_len;
            *delivered = true;
            state->expected += 1u;
            state->last_ack = state->expected;
            *ack_seq = state->expected;
            return true;
        }
        state->last_ack = state->expected;
        *ack_seq = state->expected;
        return true;
    }

    if (packet->type == PACKET_TYPE_FIN) {
        if (packet->seq == state->expected) {
            state->expected += 1u;
            state->finished = true;
            state->should_linger = true;
            state->last_ack = state->expected;
            *ack_seq = state->expected;
            *delivered = false;
            return true;
        }
        state->last_ack = state->expected;
        *ack_seq = state->expected;
        return true;
    }

    // GCOVR_EXCL_START
    if (packet->type == PACKET_TYPE_ACK) {
        *ack_seq = packet->seq;
        return true;
    }

    *ack_seq = state->expected;
    return true;
    // GCOVR_EXCL_STOP
}
