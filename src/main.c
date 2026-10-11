#include "lab.h"

#ifdef TEST
#define main main_exclude
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static void print_usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s send -s <session> [-w window] [-T timeout-ms] [-l loss]\n"
            "                  [-c corrupt] [-d dup] [-p port] <relay> <file>\n"
            "       %s recv -s <session> [-p port] <relay> <file>\n",
            argv0, argv0);
}

static bool valid_session(const char *session) {
    size_t len;
    if (session == NULL || *session == '\0') {
        return false;
    }
    len = strlen(session);
    if (len < 1u || len > 32u) {
        return false;
    }
    for (size_t i = 0u; i < len; ++i) {
        char ch = session[i];
        if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
            continue;
        }
        return false;
    }
    return true;
}

static bool valid_rate(double value) {
    return value >= 0.0 && value <= 0.5;
}

static int resolve_address(const char *host, int port, struct sockaddr_storage *ss, socklen_t *len) {
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    char service[32];
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;

    snprintf(service, sizeof(service), "%d", port);
    rc = getaddrinfo(host, service, &hints, &result);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }
    memcpy(ss, result->ai_addr, result->ai_addrlen);
    *len = (socklen_t)result->ai_addrlen;
    freeaddrinfo(result);
    return 0;
}

static int hello_and_wait(int sockfd, const char *session, bool is_sender,
                          double loss, double corrupt, double dup,
                          const struct sockaddr *peer, socklen_t peer_len) {
    char msg[256];
    char reply[512];
    int attempts = 0;

    if (is_sender) {
        snprintf(msg, sizeof(msg), "HELLO %s send %.6f %.6f %.6f", session, loss, corrupt, dup);
    } else {
        snprintf(msg, sizeof(msg), "HELLO %s recv", session);
    }

    while (attempts < 5) {
        ssize_t sent = sendto(sockfd, msg, strlen(msg), 0, peer, peer_len);
        struct pollfd pfd;
        int poll_rc;

        if (sent < 0) {
            perror("sendto");
            return 2;
        }

        pfd.fd = sockfd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        poll_rc = poll(&pfd, 1u, 1000);
        if (poll_rc <= 0) {
            ++attempts;
            continue;
        }

        memset(reply, 0, sizeof(reply));
        ssize_t received = recvfrom(sockfd, reply, sizeof(reply) - 1u, 0, NULL, NULL);
        if (received <= 0) {
            ++attempts;
            continue;
        }
        reply[received] = '\0';
        if (strncmp(reply, "OK", 2) == 0) {
            return 0;
        }
        if (strncmp(reply, "ERR ", 4) == 0) {
            fprintf(stderr, "%s\n", reply);
            return 2;
        }
        ++attempts;
    }

    fprintf(stderr, "relay failed to reply\n");
    return 2;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0u;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000u);
}

static int transmit_packets(int sockfd, const struct sockaddr_storage *relay_addr,
                            socklen_t relay_len, const Packet *packets, size_t count) {
    for (size_t i = 0u; i < count; ++i) {
        uint8_t wire[PACKET_MAX_SIZE];
        size_t written = 0u;
        if (!packet_encode(&packets[i], wire, sizeof(wire), &written)) {
            fprintf(stderr, "cannot encode packet\n");
            return -1;
        }
        if (sendto(sockfd, wire, written, 0,
                   (const struct sockaddr *)relay_addr, relay_len) != (ssize_t)written) {
            perror("sendto");
            return -1;
        }
    }
    return 0;
}

static int sender_mode(const char *relay, const char *session, const char *file_path,
                      uint32_t window, uint32_t timeout_ms,
                      double loss, double corrupt, double dup, int port) {
    struct sockaddr_storage relay_addr;
    socklen_t relay_len = 0;
    int sockfd;
    FILE *fp;
    uint8_t *data = NULL;
    size_t file_size = 0u;
    SenderState sender;
    uint64_t deadline_ms = 0u;
    int exit_code = 2;
    uint8_t recv_buf[2048];

    if (resolve_address(relay, port, &relay_addr, &relay_len) != 0) {
        return 2;
    }

    sockfd = socket(relay_addr.ss_family, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 2;
    }

    fp = fopen(file_path, "rb");
    if (fp == NULL) {
        perror(file_path);
        close(sockfd);
        return 2;
    }
    if (fseek(fp, 0L, SEEK_END) != 0) {
        perror("fseek");
        fclose(fp);
        close(sockfd);
        return 2;
    }
    long size = ftell(fp);
    if (size < 0) {
        perror("ftell");
        fclose(fp);
        close(sockfd);
        return 2;
    }
    rewind(fp);
    file_size = (size_t)size;
    data = (uint8_t *)malloc(file_size == 0u ? 1u : file_size);
    if (data == NULL) {
        fclose(fp);
        close(sockfd);
        return 2;
    }
    if (file_size > 0u) {
        if (fread(data, 1u, file_size, fp) != file_size) {
            perror("fread");
            free(data);
            fclose(fp);
            close(sockfd);
            return 2;
        }
    }
    fclose(fp);

    sender_init(&sender, window, timeout_ms);
    sender_set_file(&sender, data, file_size);
    if (sender.copy == NULL) {
        fprintf(stderr, "unable to allocate sender packet buffer\n");
        free(data);
        close(sockfd);
        return 2;
    }

    if (hello_and_wait(sockfd, session, true, loss, corrupt, dup,
                       (const struct sockaddr *)&relay_addr, relay_len) != 0) {
        free(data);
        close(sockfd);
        return 2;
    }

    deadline_ms = 0u;
    while (!sender.done) {
        Packet packet_list[64];
        size_t count = 0u;
        int timeout_ms_left;
        struct pollfd pfd;
        ssize_t received;

        count = sender_ready_packets(&sender, packet_list,
                                     sizeof(packet_list) / sizeof(packet_list[0]));
        if (count > 0u) {
            if (transmit_packets(sockfd, &relay_addr, relay_len, packet_list, count) != 0) {
                break;
            }
            if (deadline_ms == 0u) {
                deadline_ms = now_ms() + sender.timeout_ms;
            }
        }

        if (sender.base < sender.next) {
            uint64_t now = now_ms();
            if (now >= deadline_ms) {
                count = sender_on_timeout(&sender, packet_list,
                                         sizeof(packet_list) / sizeof(packet_list[0]));
                if (count > 0u &&
                    transmit_packets(sockfd, &relay_addr, relay_len, packet_list, count) != 0) {
                    break;
                }
                deadline_ms = sender.done ? 0u : now_ms() + sender.timeout_ms;
                continue;
            }
            timeout_ms_left = (int)(deadline_ms - now);
        } else {
            fprintf(stderr, "sender has no outstanding packet but is not complete\n");
            break;
        }

        pfd.fd = sockfd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int poll_result = poll(&pfd, 1u, timeout_ms_left);
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            break;
        }
        if (poll_result == 0) {
            continue;
        }

        received = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, NULL, NULL);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recvfrom");
            break;
        }
        if (received == 0) {
            continue;
        }

        Packet incoming;
        if (!packet_decode(recv_buf, (size_t)received, &incoming)) {
            continue;
        }
        if (incoming.type == PACKET_TYPE_ACK) {
            uint32_t old_base = sender.base;
            sender_on_ack(&sender, incoming.seq);
            if (sender.base > old_base && !sender.done) {
                deadline_ms = now_ms() + sender.timeout_ms;
            }
        }
    }

    if (sender.done && sender.base == sender.total_packets + 1u) {
        exit_code = 0;
    } else if (sender.done && sender.timeout_count >= 10u) {
        fprintf(stderr, "transfer failed after 10 consecutive timeouts\n");
    }

    sender_release(&sender);
    free(data);
    close(sockfd);
    return exit_code;
}

static int receiver_mode(const char *relay, const char *session, const char *file_path, int port) {
    struct sockaddr_storage relay_addr;
    socklen_t relay_len = 0;
    int sockfd;
    FILE *out;
    ReceiverState receiver;
    uint8_t recv_buf[2048];
    uint64_t last_activity;
    int exit_code = 2;

    if (resolve_address(relay, port, &relay_addr, &relay_len) != 0) {
        return 2;
    }
    sockfd = socket(relay_addr.ss_family, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 2;
    }
    out = fopen(file_path, "wb");
    if (out == NULL) {
        perror(file_path);
        close(sockfd);
        return 2;
    }

    if (hello_and_wait(sockfd, session, false, 0.0, 0.0, 0.0,
                       (const struct sockaddr *)&relay_addr, relay_len) != 0) {
        fclose(out);
        close(sockfd);
        return 2;
    }

    receiver_init(&receiver);
    last_activity = now_ms();
    while (1) {
        struct pollfd pfd;
        int poll_rc;
        ssize_t received;
        Packet packet;
        uint8_t payload[PACKET_MAX_PAYLOAD];
        size_t payload_len = 0u;
        bool delivered = false;
        uint32_t ack_seq = 0u;
        uint8_t wire[PACKET_MAX_SIZE];
        size_t written = 0u;
        uint64_t now = now_ms();
        uint64_t idle_ms = now - last_activity;
        int poll_timeout = idle_ms >= 30000u ? 0 : (int)(30000u - idle_ms);

        pfd.fd = sockfd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        poll_rc = poll(&pfd, 1u, poll_timeout);
        if (poll_rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            break;
        }
        if (poll_rc == 0) {
            fprintf(stderr, "receiver timeout\n");
            break;
        }

        received = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, NULL, NULL);
        if (received <= 0) {
            continue;
        }
        if (!packet_decode(recv_buf, (size_t)received, &packet)) {
            continue;
        }
        last_activity = now_ms();

        if (receiver_on_packet(&receiver, &packet, &ack_seq, payload, &payload_len, &delivered)) {
            if (delivered && payload_len > 0u) {
                fwrite(payload, 1u, payload_len, out);
            }
            Packet ack;
            memset(&ack, 0, sizeof(ack));
            ack.type = PACKET_TYPE_ACK;
            ack.seq = ack_seq;
            ack.length = 0u;
            ack.reserved = 0u;
            if (!packet_encode(&ack, wire, sizeof(wire), &written)) {
                continue;
            }
            if (sendto(sockfd, wire, written, 0,
                       (const struct sockaddr *)&relay_addr, relay_len) != (ssize_t)written) {
                perror("sendto");
                break;
            }
            if (packet.type == PACKET_TYPE_FIN && receiver.finished) {
                exit_code = 0;
                uint64_t linger_until = now_ms() + 2000u;
                while (now_ms() < linger_until) {
                    struct pollfd linger_pfd;
                    int remaining = (int)(linger_until - now_ms());
                    linger_pfd.fd = sockfd;
                    linger_pfd.events = POLLIN;
                    linger_pfd.revents = 0;
                    int ready = poll(&linger_pfd, 1u, remaining);
                    if (ready < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        perror("poll");
                        exit_code = 2;
                        break;
                    }
                    if (ready == 0) {
                        break;
                    }

                    received = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, NULL, NULL);
                    if (received < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        perror("recvfrom");
                        exit_code = 2;
                        break;
                    }
                    if (packet_decode(recv_buf, (size_t)received, &packet) &&
                        packet.type == PACKET_TYPE_FIN &&
                        packet.seq + 1u == receiver.expected) {
                        if (sendto(sockfd, wire, written, 0,
                                   (const struct sockaddr *)&relay_addr, relay_len) != (ssize_t)written) {
                            perror("sendto");
                            exit_code = 2;
                            break;
                        }
                    }
                }
                fclose(out);
                close(sockfd);
                return exit_code;
            }
        }
    }

    fclose(out);
    close(sockfd);
    return exit_code;
}

int main(int argc, char **argv) {
    const char *mode = NULL;
    const char *session = NULL;
    const char *relay = NULL;
    const char *file = NULL;
    uint32_t window = 8u;
    uint32_t timeout_ms = 250u;
    double loss = 0.0;
    double corrupt = 0.0;
    double dup = 0.0;
    int port = 4250;
    bool send_mode = false;
    bool recv_mode = false;
    int opt;

    if (argc == 1) {
        print_usage(argv[0]);
        return 0;
    }

    mode = argv[1];
    if (strcmp(mode, "send") == 0) {
        send_mode = true;
    } else if (strcmp(mode, "recv") == 0) {
        recv_mode = true;
    } else {
        print_usage(argv[0]);
        return 1;
    }

    opterr = 0;
    optind = 2;
    while ((opt = getopt(argc, argv, ":s:w:T:l:c:d:p:")) != -1) {
        switch (opt) {
            case 's':
                session = optarg;
                break;
            case 'w':
                window = (uint32_t)strtoul(optarg, NULL, 10);
                break;
            case 'T':
                timeout_ms = (uint32_t)strtoul(optarg, NULL, 10);
                break;
            case 'l':
                loss = strtod(optarg, NULL);
                break;
            case 'c':
                corrupt = strtod(optarg, NULL);
                break;
            case 'd':
                dup = strtod(optarg, NULL);
                break;
            case 'p':
                port = (int)strtol(optarg, NULL, 10);
                break;
            case '?':
                print_usage(argv[0]);
                return 1;
            case ':':
                print_usage(argv[0]);
                return 1;
            default:
                break;
        }
    }

    if (session == NULL || !valid_session(session)) {
        print_usage(argv[0]);
        return 1;
    }
    if (!send_mode && !recv_mode) {
        print_usage(argv[0]);
        return 1;
    }
    if (window < 1u || window > 64u) {
        print_usage(argv[0]);
        return 1;
    }
    if (!valid_rate(loss) || !valid_rate(corrupt) || !valid_rate(dup)) {
        print_usage(argv[0]);
        return 1;
    }
    if (optind + 1 >= argc) {
        print_usage(argv[0]);
        return 1;
    }
    relay = argv[optind];
    file = argv[optind + 1];

    if (send_mode) {
        return sender_mode(relay, session, file, window, timeout_ms, loss, corrupt, dup, port);
    }
    if (recv_mode) {
        return receiver_mode(relay, session, file, port);
    }
    print_usage(argv[0]);
    return 1;
}
