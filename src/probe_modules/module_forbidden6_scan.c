// probe module for performing TCP forbidden payload scans in IPv6

// Needed for asprintf
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"

#define ZMAPV6_TCP_SYNSCAN_TCP_HEADER_LEN 20
#define ZMAPV6_TCP_SYNSCAN_PACKET_LEN 74

#ifndef HOST
#define HOST "www.youporn.com"
#endif
//#define TCP_FLAGS TH_PUSH | TH_ACK
#define TCP_FLAGS TH_PUSH | TH_ACK
#define PAYLOAD "GET / HTTP/1.1\r\nHost: " HOST "\r\n\r\n"
#define PAYLOAD_LEN strlen(PAYLOAD)
#define TOTAL_LEN sizeof(struct ip) + sizeof(struct tcphdr)
#define TOTAL_LEN_PAYLOAD                                                      \
	sizeof(struct ip) + sizeof(struct tcphdr) + PAYLOAD_LEN
#define ETHER_LEN sizeof(struct ether_header)
#define IP_LEN sizeof(struct ip)

probe_module_t module_forbidden6_scan;
static uint32_t num_ports;

static int forbidden6scan_global_initialize(struct state_conf *state)
{
	printf("Starting module. Packet out size: %d\n",TOTAL_LEN_PAYLOAD + TOTAL_LEN);
	num_ports = state->source_port_last - state->source_port_first + 1;
	if (asprintf((char **restrict)&module_forbidden6_scan.pcap_filter,
		     "%s && ip6 dst host %s",
		     module_forbidden6_scan.pcap_filter,
		     state->ipv6_source_ip) == -1) {
		return 1;
	}
	return EXIT_SUCCESS;
}

static int forbidden6scan_init_perthread(void *buf, macaddr_t *src,
					macaddr_t *gw, port_h_t dst_port,
					__attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header_ethertype(eth_header, src, gw, ETHERTYPE_IPV6);
	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(&eth_header[1]);
	uint16_t len = ZMAPV6_TCP_SYNSCAN_TCP_HEADER_LEN;
	// uint16_t len = htons(sizeof(struct ip6_hdr) + sizeof(struct tcphdr));

	make_ip6_header(ip6_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip6_header[1]);

	make_tcp_header(tcp_header, dst_port, TH_SYN);
	return EXIT_SUCCESS;
}
static int forbidden6scan_init_perthread2(void *buf, macaddr_t *src,
					 macaddr_t *gw, port_h_t dst_port,
					 __attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header_ethertype(eth_header, src, gw, ETHERTYPE_IPV6);
	struct ip *ip6_header = (struct ip6_hdr *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + PAYLOAD_LEN);
	make_ip6_header(ip6_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip6_header[1]);

	make_tcp_header(tcp_header, dst_port, TCP_FLAGS);
	char *payload = (char *)(&tcp_header[1]);
	memcpy(payload, PAYLOAD, PAYLOAD_LEN);
	return EXIT_SUCCESS;
}

static int forbidden6scan_make_packet(void *buf, UNUSED size_t *buf_len,
				     ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
				     uint8_t ttl, uint32_t *validation,
				     int probe_num, UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip6_header[1]);
	// Subtract one for the SYN packet
	// uint32_t tcp_seq = ntohl(htonl(validation[0]) - 1);
	uint32_t tcp_seq = validation[0];
	// uint32_t tcp_ack = 0;
	//validation[2]; // get_src_port() below uses validation 1 internally.

	ip6_header->ip6_src = ((struct in6_addr *) arg )[0];
	ip6_header->ip6_dst = ((struct in6_addr *) arg)[1];
	ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;

	tcp_header->th_sport = htons(get_src_port(num_ports, probe_num, validation));
	tcp_header->th_seq = tcp_seq;
	// tcp_header->th_sum = 0;
	unsigned short len_tcp = ZMAPV6_TCP_SYNSCAN_TCP_HEADER_LEN;
	tcp_header->th_sum = ipv6_payload_checksum(
	    len_tcp, &ip6_header->ip6_src, &ip6_header->ip6_dst,
	    (unsigned short *)tcp_header, IPPROTO_TCP);

	// No ip checksum in IPv6 IP header
	*buf_len = ZMAPV6_TCP_SYNSCAN_PACKET_LEN;

	return EXIT_SUCCESS;
}

static int forbidden6scan_make_packet2(void *buf, UNUSED size_t *buf_len,
				      ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
				      uint8_t ttl, uint32_t *validation,
				      int probe_num, UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip6_header[1]);
	uint32_t tcp_seq = validation[0];
	uint32_t tcp_ack =validation[2]; // get_src_port() below uses validation 1 internally.

	ip6_header->ip6_src = ((struct in6_addr *)arg)[0];
	ip6_header->ip6_dst = ((struct in6_addr *)arg)[1];
	ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;

	tcp_header->th_sport = htons(get_src_port(num_ports, probe_num, validation));
	tcp_header->th_seq = validation[0];
	tcp_header->th_ack = tcp_ack;
	tcp_header->th_sum = 0;

	printf(src_ip);
	tcp_header->th_sum = ipv6_payload_checksum(
	    sizeof(struct tcphdr) + PAYLOAD_LEN, &ip6_header->ip6_src,
	    &ip6_header->ip6_dst, (unsigned short *)tcp_header, IPPROTO_TCP);

	return EXIT_SUCCESS;
}

void forbidden6scan_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip6_hdr *iph = (struct ip6_hdr *)&ethh[1];
	struct tcphdr *tcph = (struct tcphdr *)&iph[1];
	fprintf(fp,
		"tcp { source: %u | dest: %u | seq: %u | checksum: %#04X }\n",
		ntohs(tcph->th_sport), ntohs(tcph->th_dport),
		ntohl(tcph->th_seq), ntohs(tcph->th_sum));
	fprintf_ipv6_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

static int forbidden6scan_validate_packet(const struct ip *ip_hdr, uint32_t len,
        __attribute__((unused)) uint32_t *src_ip,
        uint32_t *validation)
{
	struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *)ip_hdr;

	if (ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP) {
		return 0;
	}
	// if ((4 * ip_hdr->ip_hl + sizeof(struct tcphdr)) + 1 > len) {
	// 	// buffer not large enough to contain expected tcp header 
	// 	return 0;
	// }

	if ((ntohs(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen)) > len) {
		// buffer not large enough to contain expected tcp header, i.e. IPv6 payload
		return 0;
	}

	struct tcphdr *tcp_hdr = (struct tcphdr *)(&ipv6_hdr[1]);
	uint16_t sport = tcp_hdr->th_sport;
	uint16_t dport = tcp_hdr->th_dport;

	// validate source port
	if (ntohs(sport) != zconf.target_port) {
		return 0;
	}

	// validate destination port
	if (!check_dst_port(ntohs(dport), num_ports, validation)) {
		return 0;
	}

	if ((htonl(tcp_hdr->th_ack) != htonl(validation[0]) + PAYLOAD_LEN) &&
	    (htonl(tcp_hdr->th_ack) != htonl(validation[0])) &&
	    (htonl(tcp_hdr->th_seq) != htonl(validation[2]))) {
		return 0;
	}

	return 1;
}


static void forbidden6scan_process_packet(const u_char *packet,
        uint32_t len,
        fieldset_t *fs,
        __attribute__((unused))
        uint32_t *validation)
{
	// struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	// struct tcphdr *tcp =(struct tcphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);

	struct ether_header *eth_hdr = (struct ether_header *)packet;
	struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *)(&eth_hdr[1]);
	struct tcphdr *tcp_hdr = (struct tcphdr *)(&ipv6_hdr[1]);

	char *payload = (char *)(&tcp_hdr[1]);
	int mylen = ntohs(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen);
	int payloadlen = mylen - IP_LEN - (tcp_hdr->th_off * 4);
	mylen += ETHER_LEN;

	fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp_hdr->th_sport));
	fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp_hdr->th_dport));
	fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp_hdr->th_seq));
	fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp_hdr->th_ack));
	fs_add_uint64(fs, "window", (uint64_t)ntohs(tcp_hdr->th_win));
	fs_add_uint64(fs, "payloadlen", (uint64_t)payloadlen);
	fs_add_uint64(fs, "len", (uint64_t)mylen);
	fs_add_uint64(fs, "flags", (uint64_t)tcp_hdr->th_flags);

	// ip_
	// fs_add_uint64(fs, "ipid", (uint64_t)ntohs(ipv6_hdr->ip_id));

    // Attempt to track why an IP responded - did it acknolwedge our payload or not? 
    // If it acknowledges our payload, than it is probably responding to our payload
    // otherwise, it may just be sending us SYN/ACKs or responses
    if (htonl(tcp_hdr->th_ack) == htonl(validation[0]) + PAYLOAD_LEN) {
	    fs_add_uint64(fs, "validation_type", 0);
    } else if ((htonl(tcp_hdr->th_ack) == htonl(validation[0])) ||
               (htonl(tcp_hdr->th_seq) == htonl(validation[2]))) {
	    fs_add_uint64(fs, "validation_type", 1);
    } else {
	    fs_add_uint64(fs, "validation_type", 2);
    }

	fs_add_string(fs, "classification", "", 0);
	//fs_add_string(fs, "classification", (char *)payload, 0);
	fs_add_bool(fs, "success", 1);
}


static fielddef_t myfields[] = {
    {.name = "sport", .type = "int", .desc = "TCP source port"},
    {.name = "dport", .type = "int", .desc = "TCP destination port"},
    {.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
    {.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
    {.name = "window", .type = "int", .desc = "TCP window"},
    {.name = "payloadlen", .type = "int", .desc = "Payload Length"},
    {.name = "len", .type = "int", .desc = "Packet size"},
    {.name = "flags", .type = "int", .desc = "Packet flags"},
    {.name = "ipid", .type = "int", .desc = "IP Identification"},
    {.name = "validation_type", .type = "int", .desc = "Type of Validation"},
    {.name = "classification",.type = "string",.desc = "packet classification"},
    {.name = "success", .type = "bool", .desc = "is response considered success"}};

probe_module_t module_forbidden6_scan = {
    .name = "forbidden6_scan",
    .max_packet_length = ZMAPV6_TCP_SYNSCAN_PACKET_LEN,
    .max_packet2_length = TOTAL_LEN_PAYLOAD + ETHER_LEN,
    .pcap_filter = "ip6 proto 6 && tcp",
    .pcap_snaplen = 116, // was 96 for IPv4
    .port_args = 1,
    .global_initialize = &forbidden6scan_global_initialize,
    .thread_initialize = &forbidden6scan_init_perthread,
    .thread_initialize2 = &forbidden6scan_init_perthread2,
    .make_packet = &forbidden6scan_make_packet,
    .make_packet2 = &forbidden6scan_make_packet2,
    .print_packet = &forbidden6scan_print_packet,
    .process_packet = &forbidden6scan_process_packet,
    .validate_packet = &forbidden6scan_validate_packet,
    .close = NULL,
    .helptext = "Probe module that sends an IPv6+TCP SYN packet to a specific "
		"port. Possible classifications are: synack and rst. A "
		"SYN-ACK packet is considered a success and a reset packet "
		"is considered a failed response.",

    .fields = myfields,
    .numfields = 12};
