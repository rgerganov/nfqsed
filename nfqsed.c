/*
Copyright (c) 2015 Radoslav Gerganov <rgerganov@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>

struct ip_hdr {
    uint8_t vhl;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t sum;
    uint16_t src[2];
    uint16_t dst[2];
};

struct tcp_hdr {
    uint16_t sport;
    uint16_t dport;
    unsigned int seq;
    unsigned int ack;
    uint8_t off;
    uint8_t flags;
    uint16_t win;
    uint16_t sum;
    uint16_t urp;
};

#define IP_HL(ip)   (((ip)->vhl) & 0x0f)
#define TH_OFF(th)  (((th)->off & 0xf0) >> 4)

struct rule_t {
    uint8_t *val1;
    uint8_t *val2;
    int length;
    struct rule_t *next;
};

struct rule_t *rules = NULL;
int verbose = 0;
int queue_num = 0;

void usage()
{
    fprintf(stderr, "Usage: nfqsed -s /val1/val2 [-s /val1/val2] [-f file]\n"
            "  -s val1/val2     - replaces occurences of val1 with val2 in the packet payload\n"
            "  -f file          - read replacement rules from the specified file\n"
            "  -v               - be verbose\n");
    exit(1);
}

void print_rule(const struct rule_t *rule)
{
    int i = 0;
    for (i = 0 ; i < rule->length ; i++) {
        printf("%x", rule->val1[i]);
    }
    printf(" -> ");
    for (i = 0 ; i < rule->length ; i++) {
        printf("%x", rule->val2[i]);
    }
    printf("\n");
}

void add_rule(const char *rule_str)
{
    char delim = rule_str[0];
    char *pos = NULL;
    int length = 0;
    struct rule_t *rule;
    if (strlen(rule_str) < 4) {
        fprintf(stderr, "rule too short: %s\n", rule_str);
        exit(1);
    }
    pos = strchr(rule_str+1, delim);
    if (!pos) {
        fprintf(stderr, "incorrect rule: %s\n", rule_str);
        exit(1);
    }
    length = strlen(pos+1);
    if (pos - rule_str - 1 != length) {
        fprintf(stderr, "val1 and val2 must be the same length: %s\n", rule_str);
        exit(1);
    }
    rule = malloc(sizeof(struct rule_t));
    rule->val1 = malloc(length);
    memcpy(rule->val1, rule_str + 1, length);
    rule->val2 = malloc(length);
    memcpy(rule->val2, pos + 1, length);
    rule->length = length;
    rule->next = NULL;
    if (rules) {
        rule->next = rules;
        rules = rule;
    } else {
        rules = rule;
    }
}

void load_rules(const char *rules_file)
{
    FILE *f;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    f = fopen(rules_file, "r");
    if (!f) {
        fprintf(stderr, "cannot open %s", rules_file);
        exit(1);
    }
    while ((read = getline(&line, &len, f)) != -1) {
        if (line[0] == '#' || read == 1) {
            // skip comments and empty lines
            continue;
        }
        if (line[read-1] == '\n') {
            line[read-1] = 0;
        }
        add_rule(line);
    }
    free(line);
    fclose(f);
}

uint16_t tcp_sum(uint16_t len_tcp, uint16_t *src_addr, uint16_t *dest_addr, uint8_t *buff)
{
    uint16_t prot_tcp = 6;
    uint32_t sum = 0;
    int i = 0;

    sum += ntohs(src_addr[0]);
    sum += ntohs(src_addr[1]);
    sum += ntohs(dest_addr[0]);
    sum += ntohs(dest_addr[1]);
    sum += len_tcp;
    sum += prot_tcp;
    for (i=0; i<(len_tcp/2); i++) {
        sum += ntohs((buff[i*2+1] << 8) | buff[i*2]);
    }
    if ((len_tcp % 2) == 1) {
        sum += buff[len_tcp-1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = ~sum;
    return htons((uint16_t) sum);
}

uint8_t *find(const struct rule_t *rule, uint8_t *payload, int payload_length)
{
    int rule_len = rule->length;
    int i = 0, j = 0, match = 0;
    for (i = 0 ; i < payload_length - rule_len ; i++) {
        match = 1;
        for (j = 0 ; j < rule_len ; j++) {
            if (payload[i+j] != rule->val1[j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            return payload + i;
        }
    }
    return NULL;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    int id = 0, len = 0;
    struct nfqnl_msg_packet_hdr *ph;
    uint8_t *payload=NULL, *tcp_payload, *pos;
    struct ip_hdr *ip;
    struct tcp_hdr *tcp;
    uint16_t ip_size = 0, tcp_size = 0;
    struct rule_t *rule = rules;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    len = nfq_get_payload(nfa, &payload);
    if (len < 0) {
        fprintf(stderr, "Error getting payload\n");
        return len;
    }
    ip = (struct ip_hdr*) payload;
    if (ip->proto != 6) {
        // only tcp is supported
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    ip_size = IP_HL(ip)*4;
    tcp = (struct tcp_hdr*)(payload + ip_size);
    tcp_size = TH_OFF(tcp)*4;
    tcp_payload = (uint8_t*)(payload + ip_size + tcp_size);
    
    while (rule) {
        while ((pos = find(rule, tcp_payload, len - ip_size - tcp_size)) != NULL) {
            if (verbose) {
                printf("rule match, changing payload: ");
                print_rule(rule);
            }
            memcpy(pos, rule->val2, rule->length);
        }
        rule = rule->next;
    }
    tcp->sum = 0;
    tcp->sum = tcp_sum(len-ip_size, ip->src, ip->dst, (uint8_t*) tcp);
    return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
}

void read_queue()
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '%d'\n", queue_num);
    qh = nfq_create_queue(h, queue_num, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        if (verbose) {
            printf("packet received\n");
        }
        nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);
}

int main(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "vs:f:q:")) != -1) {
        switch (opt) {
            case 'v':
                verbose = 1;
                break;
            case 's':
                add_rule(optarg);
                break;
            case 'f':
                load_rules(optarg);
                break;
            case 'q':
                queue_num = atoi(optarg);
                break;
            default:
                usage();
        }
    }
    if (!rules) {
        fprintf(stderr, "no rules defined, exiting\n");
        return 1;
    }
    if (verbose) {
        struct rule_t *rule = rules;
        printf("Rules (in hex):\n");
        while (rule) {
            printf("  ");
            print_rule(rule);
            rule = rule->next;
        }
    }
    read_queue();
    return 0;
}

