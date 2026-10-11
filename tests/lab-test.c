#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/unity.h"
#include "../src/lab.h"

void setUp(void) {
}

void tearDown(void) {
}

static void build_packet(uint8_t type, uint32_t seq, const uint8_t *payload,
                         size_t payload_len, Packet *packet) {
  memset(packet, 0, sizeof(*packet));
  packet->type = type;
  packet->seq = seq;
  packet->length = (uint16_t)payload_len;
  if (payload_len > 0u) {
    memcpy(packet->payload, payload, payload_len);
  }
  packet->checksum = 0u;
  packet->reserved = 0u;
}

static bool channel_copy(uint8_t *buffer, size_t length) {
  int event = rand() % 100;
  if (event < 20) {
    return false;
  }
  if (event < 40 && length > 0u) {
    size_t bit = (size_t)rand() % (length * 8u);
    buffer[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));
  }
  return true;
}

static void channel_ack_to_sender(SenderState *sender, const Packet *ack) {
  uint8_t wire[PACKET_MAX_SIZE];
  size_t written = 0u;
  if (!packet_encode(ack, wire, sizeof(wire), &written) || !channel_copy(wire, written)) {
    return;
  }
  Packet received;
  if (packet_decode(wire, written, &received)) {
    sender_on_ack(sender, received.seq);
  }
  if (rand() % 100 < 20 && packet_decode(wire, written, &received)) {
    sender_on_ack(sender, received.seq);
  }
}

static void channel_data_to_receiver(SenderState *sender, ReceiverState *receiver,
                                     const Packet *sent, uint8_t *output,
                                     size_t *output_length) {
  uint8_t wire[PACKET_MAX_SIZE];
  size_t written = 0u;
  Packet received;
  uint8_t payload[PACKET_MAX_PAYLOAD];
  size_t payload_length = 0u;
  uint32_t ack_seq = 0u;
  bool delivered = false;
  int copies;

  if (!packet_encode(sent, wire, sizeof(wire), &written) || !channel_copy(wire, written)) {
    return;
  }
  copies = rand() % 100 < 20 ? 2 : 1;
  for (int i = 0; i < copies; ++i) {
    if (!packet_decode(wire, written, &received) ||
        !receiver_on_packet(receiver, &received, &ack_seq, payload,
                            &payload_length, &delivered)) {
      continue;
    }
    if (delivered && payload_length > 0u) {
      memcpy(output + *output_length, payload, payload_length);
      *output_length += payload_length;
    }
    Packet ack;
    memset(&ack, 0, sizeof(ack));
    ack.type = PACKET_TYPE_ACK;
    ack.seq = ack_seq;
    channel_ack_to_sender(sender, &ack);
  }
}

void test_rfc1071_example(void) {
  static const uint8_t bytes[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
  TEST_ASSERT_EQUAL_UINT16(0x220d, packet_checksum(bytes, sizeof(bytes)));
}

void test_packet_round_trip_and_checksum_bitflip(void) {
  uint8_t buffer[PACKET_MAX_SIZE];
  uint8_t decode_buf[PACKET_MAX_SIZE];
  Packet packet;
  Packet decoded;
  size_t written = 0u;
  const uint8_t payload[] = { 'H', 'i', '!' };

  build_packet(PACKET_TYPE_DATA, 2u, payload, sizeof(payload), &packet);
  TEST_ASSERT_TRUE(packet_encode(&packet, buffer, sizeof(buffer), &written));
  TEST_ASSERT_EQUAL_UINT32(13u, (uint32_t)written);
  memcpy(decode_buf, buffer, sizeof(buffer));
  TEST_ASSERT_TRUE(packet_decode(buffer, written, &decoded));
  TEST_ASSERT_EQUAL_UINT8(PACKET_TYPE_DATA, decoded.type);
  TEST_ASSERT_EQUAL_UINT32(2u, decoded.seq);
  TEST_ASSERT_EQUAL_UINT16(3u, decoded.length);
  TEST_ASSERT_EQUAL_UINT8('H', decoded.payload[0]);
  TEST_ASSERT_EQUAL_UINT8('i', decoded.payload[1]);
  TEST_ASSERT_EQUAL_UINT8('!', decoded.payload[2]);

  decode_buf[0] ^= 0x01u;
  TEST_ASSERT_FALSE(packet_decode(decode_buf, written, &decoded));
}

void test_packet_rejects_invalid_datagrams(void) {
  uint8_t short_data[9] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint8_t mismatch[11] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00};
  uint8_t bad_type[10] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  Packet packet;

  TEST_ASSERT_FALSE(packet_decode(short_data, sizeof(short_data), &packet));
  TEST_ASSERT_FALSE(packet_decode(mismatch, sizeof(mismatch), &packet));
  TEST_ASSERT_FALSE(packet_decode(bad_type, sizeof(bad_type), &packet));
}

void test_sender_window_and_ack_logic(void) {
  uint8_t file[4096];
  SenderState sender;
  Packet out[16];
  size_t sent;
  memset(file, 0xA5, sizeof(file));

  sender_init(&sender, 4u, 250u);
  sender_set_file(&sender, file, sizeof(file));

  sent = sender_ready_packets(&sender, out, sizeof(out) / sizeof(out[0]));
  TEST_ASSERT_EQUAL_UINT32(4u, (uint32_t)sent);
  TEST_ASSERT_EQUAL_UINT32(0u, sender.base);
  TEST_ASSERT_EQUAL_UINT32(4u, sender.next);

  sent = sender_on_timeout(&sender, out, sizeof(out) / sizeof(out[0]));
  TEST_ASSERT_EQUAL_UINT32(4u, (uint32_t)sent);

  sender_on_ack(&sender, 2u);
  TEST_ASSERT_EQUAL_UINT32(2u, sender.base);

  sender_on_ack(&sender, 2u);
  TEST_ASSERT_EQUAL_UINT32(2u, sender.base);

  sender_on_ack(&sender, 4u);
  TEST_ASSERT_EQUAL_UINT32(4u, sender.base);
  sender_release(&sender);
}

void test_sender_retransmit_and_give_up_after_ten_timeouts(void) {
  uint8_t file[5000];
  SenderState sender;
  Packet out[32];
  size_t sent;
  memset(file, 0x42, sizeof(file));

  sender_init(&sender, 1u, 100u);
  sender_set_file(&sender, file, sizeof(file));
  sent = sender_ready_packets(&sender, out, sizeof(out) / sizeof(out[0]));
  TEST_ASSERT_GREATER_THAN_UINT(0u, sent);

  sender_on_ack(&sender, 1u);
  for (int i = 0; i < 10; ++i) {
    sender_on_timeout(&sender, out, sizeof(out) / sizeof(out[0]));
  }
  TEST_ASSERT_GREATER_OR_EQUAL_UINT32(sender.timeout_count, 10u);
  sender_release(&sender);
}

void test_receiver_duplicate_gap_and_repeated_fin(void) {
  ReceiverState receiver;
  uint8_t payload[] = {'A', 'B', 'C'};
  Packet data, dup, gap, fin;
  uint8_t out_payload[PACKET_MAX_PAYLOAD];
  size_t out_len = 0u;
  uint32_t ack_seq = 0u;
  bool delivered = false;

  receiver_init(&receiver);

  build_packet(PACKET_TYPE_DATA, 0u, payload, sizeof(payload), &data);
  TEST_ASSERT_TRUE(receiver_on_packet(&receiver, &data, &ack_seq, out_payload, &out_len, &delivered));
  TEST_ASSERT_TRUE(delivered);
  TEST_ASSERT_EQUAL_UINT32(1u, ack_seq);

  TEST_ASSERT_TRUE(receiver_on_packet(&receiver, &data, &ack_seq, out_payload, &out_len, &delivered));
  TEST_ASSERT_EQUAL_UINT32(1u, ack_seq);

  build_packet(PACKET_TYPE_DATA, 2u, payload, sizeof(payload), &gap);
  TEST_ASSERT_TRUE(receiver_on_packet(&receiver, &gap, &ack_seq, out_payload, &out_len, &delivered));
  TEST_ASSERT_EQUAL_UINT32(1u, ack_seq);

  build_packet(PACKET_TYPE_FIN, 1u, NULL, 0u, &fin);
  TEST_ASSERT_TRUE(receiver_on_packet(&receiver, &fin, &ack_seq, out_payload, &out_len, &delivered));
  TEST_ASSERT_EQUAL_UINT32(2u, ack_seq);

  TEST_ASSERT_TRUE(receiver_on_packet(&receiver, &fin, &ack_seq, out_payload, &out_len, &delivered));
  TEST_ASSERT_EQUAL_UINT32(2u, ack_seq);
}

void test_sender_empty_file_and_exact_multiple(void) {
  uint8_t empty_file[1] = {0};
  uint8_t exact[FILE_CHUNK_SIZE * 2u];
  SenderState sender;
  Packet out[8];
  size_t sent;

  memset(exact, 0xFF, sizeof(exact));
  sender_init(&sender, 8u, 250u);
  sender_set_file(&sender, empty_file, 0u);
  sent = sender_ready_packets(&sender, out, 8u);
  TEST_ASSERT_EQUAL_UINT32(1u, (uint32_t)sent);
  TEST_ASSERT_EQUAL_UINT8(PACKET_TYPE_FIN, out[0].type);
  TEST_ASSERT_EQUAL_UINT32(0u, sender.total_packets);
  sender_release(&sender);

  sender_init(&sender, 8u, 250u);
  sender_set_file(&sender, exact, sizeof(exact));
  sent = sender_ready_packets(&sender, out, 8u);
  TEST_ASSERT_EQUAL_UINT32(2u, (uint32_t)sent);
  TEST_ASSERT_EQUAL_UINT32(2u, sender.next);
  sender_on_ack(&sender, 2u);
  sent = sender_ready_packets(&sender, out, 8u);
  TEST_ASSERT_EQUAL_UINT32(1u, (uint32_t)sent);
  TEST_ASSERT_EQUAL_UINT8(PACKET_TYPE_FIN, out[0].type);
  sender_release(&sender);
}

void test_end_to_end_state_machine_channel(void) {
  uint8_t input[4096];
  uint8_t output[sizeof(input)];
  memset(input, 0xC3u, sizeof(input));

  for (unsigned seed = 7u; seed < 10u; ++seed) {
    SenderState sender;
    ReceiverState receiver;
    Packet packets[64];
    size_t output_length = 0u;
    bool successful = false;
    srand(seed);
    memset(output, 0, sizeof(output));
    sender_init(&sender, 8u, 100u);
    sender_set_file(&sender, input, sizeof(input));
    receiver_init(&receiver);

    for (unsigned step = 0u; step < 1000u && !sender.done; ++step) {
      size_t count = sender_ready_packets(&sender, packets,
                                          sizeof(packets) / sizeof(packets[0]));
      if (count == 0u) {
        if (sender.base < sender.next) {
          count = sender_on_timeout(&sender, packets,
                                    sizeof(packets) / sizeof(packets[0]));
        } else {
          break;
        }
      }
      for (size_t i = 0u; i < count; ++i) {
        channel_data_to_receiver(&sender, &receiver, &packets[i],
                                 output, &output_length);
      }
    }

    successful = sender.done && sender.base == sender.total_packets + 1u;
    TEST_ASSERT_TRUE(successful);
    TEST_ASSERT_EQUAL_UINT32(sizeof(input), (uint32_t)output_length);
    TEST_ASSERT_EQUAL_MEMORY(input, output, sizeof(input));
    sender_release(&sender);
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_rfc1071_example);
  RUN_TEST(test_packet_round_trip_and_checksum_bitflip);
  RUN_TEST(test_packet_rejects_invalid_datagrams);
  RUN_TEST(test_sender_window_and_ack_logic);
  RUN_TEST(test_sender_retransmit_and_give_up_after_ten_timeouts);
  RUN_TEST(test_receiver_duplicate_gap_and_repeated_fin);
  RUN_TEST(test_sender_empty_file_and_exact_multiple);
  RUN_TEST(test_end_to_end_state_machine_channel);
  return UNITY_END();
}
