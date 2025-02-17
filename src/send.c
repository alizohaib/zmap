/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "send.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "../lib/random.h"
#include "../lib/blocklist.h"
#include "../lib/lockfd.h"
#include "../lib/pbm.h"

#include "aesrand.h"
#include "get_gateway.h"
#include "iterator.h"
#include "probe_modules/packet.h"
#include "probe_modules/probe_modules.h"
#include "shard.h"
#include "state.h"
#include "validate.h"
#include "ipv6_target_file.h"

// OS specific functions called by send_run
static inline int send_packet(sock_t sock, void *buf, int len, uint32_t idx);
static inline int send_run_init(sock_t sock);

// Include the right implementations
#if defined(PFRING)
#include "send-pfring.h"
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) ||     \
    defined(__DragonFly__)
#include "send-bsd.h"
#else /* LINUX */
#include "send-linux.h"
#endif /* __APPLE__ || __FreeBSD__ || __NetBSD__ || __DragonFly__ */

// The iterator over the cyclic group

// Lock for send run
static pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;

// Source ports for outgoing packets
static uint16_t num_src_ports;

// IPv6
static int ipv6 = 0;
static struct in6_addr ipv6_src;


void sig_handler_increase_speed(UNUSED int signal)
{
	int old_rate = zconf.rate;
	zconf.rate += (zconf.rate * 0.05);
	log_info("send", "send rate increased from %i to %i pps.", old_rate,
		 zconf.rate);
}

void sig_handler_decrease_speed(UNUSED int signal)
{
	int old_rate = zconf.rate;
	zconf.rate -= (zconf.rate * 0.05);
	log_info("send", "send rate decreased from %i to %i pps.", old_rate,
		 zconf.rate);
}

// global sender initialize (not thread specific)
iterator_t *send_init(void)
{
	// IPv6
	if (zconf.ipv6_target_filename) {
		ipv6 = 1;
		int ret = inet_pton(AF_INET6, (char *) zconf.ipv6_source_ip, &ipv6_src);
		if (ret != 1) {
			log_fatal("send", "could not read valid IPv6 src address, inet_pton returned `%d'", ret);
		}
		ipv6_target_file_init(zconf.ipv6_target_filename);
	}

	// generate a new primitive root and starting position
	iterator_t *it;
	uint32_t num_subshards =
	    (uint32_t)zconf.senders * (uint32_t)zconf.total_shards;
	if (num_subshards > blocklist_count_allowed()) {
		log_fatal("send", "senders * shards > allowed probes");
	}
	if (zsend.max_targets && (num_subshards > zsend.max_targets)) {
		log_fatal("send", "senders * shards > max targets");
	}
	it = iterator_init(zconf.senders, zconf.shard_num, zconf.total_shards);
	// determine the source address offset from which we'll send packets
	struct in_addr temp;
	temp.s_addr = zconf.source_ip_addresses[0];
	log_debug("send", "srcip_first: %s", inet_ntoa(temp));
	temp.s_addr = zconf.source_ip_addresses[zconf.number_source_ips - 1];
	log_debug("send", "srcip_last: %s", inet_ntoa(temp));

	// process the source port range that ZMap is allowed to use
	num_src_ports = zconf.source_port_last - zconf.source_port_first + 1;
	log_debug("send", "will send from %u address%s on %hu source ports",
		  zconf.number_source_ips,
		  ((zconf.number_source_ips == 1) ? "" : "es"), num_src_ports);
	// global initialization for send module
	assert(zconf.probe_module);
	if (zconf.probe_module->global_initialize) {
		if (zconf.probe_module->global_initialize(&zconf)) {
			log_fatal(
			    "send",
			    "global initialization for probe module failed.");
		}
	}

	// only allow bandwidth or rate
	if (zconf.bandwidth > 0 && zconf.rate > 0) {
		log_fatal(
		    "send",
		    "must specify rate or bandwidth, or neither, not both.");
	}

	// Convert specified bandwidth to packet rate. This is an estimate using the
	// max packet size a probe module will generate.
	if (zconf.bandwidth > 0) {
		size_t pkt_len = zconf.probe_module->max_packet_length + zconf.probe_module->max_packet2_length;
		pkt_len *= 8;
		// 7 byte MAC preamble, 1 byte Start frame, 4 byte CRC, 12 byte
		// inter-frame gap
		pkt_len += 8 * 24;
		// adjust calculated length if less than the minimum size of an
		// ethernet frame
		if (pkt_len < 84 * 8) {
			pkt_len = 84 * 8;
		}
		// rate is a uint32_t so, don't overflow
		if (zconf.bandwidth / pkt_len > 0xFFFFFFFFu) {
			zconf.rate = 0;
		} else {
			zconf.rate = zconf.bandwidth / pkt_len;
			if (zconf.rate == 0) {
				log_warn(
				    "send",
				    "bandwidth %lu bit/s is slower than 1 pkt/s, "
				    "setting rate to 1 pkt/s",
				    zconf.bandwidth);
				zconf.rate = 1;
			}
		}
		log_debug(
		    "send",
		    "using bandwidth %lu bits/s for %zu byte probe, rate set to %d pkt/s",
		    zconf.bandwidth, pkt_len / 8, zconf.rate);
	}
	// convert default placeholder to default value
	if (zconf.rate == -1) {
		// default 10K pps
		zconf.rate = 10000;
	}
	// log rate, if explicitly specified
	if (zconf.rate < 0) {
		log_fatal("send", "rate impossibly slow");
	}
	if (zconf.rate > 0 && zconf.bandwidth <= 0) {
		log_debug("send", "rate set to %d pkt/s", zconf.rate);
	}
	// Get the source hardware address, and give it to the probe
	// module
	if (!zconf.hw_mac_set) {
		if (get_iface_hw_addr(zconf.iface, zconf.hw_mac)) {
			log_fatal(
			    "send",
			    "ZMap could not retrieve the hardware (MAC) address for "
			    "the interface \"%s\". You likely do not privileges to open a raw packet socket. "
			    "Are you running as root or with the CAP_NET_RAW capability? If you are, you "
			    "may need to manually set the source MAC address with the \"--source-mac\" flag.",
			    zconf.iface);
			return NULL;
		}
		log_debug(
		    "send",
		    "no source MAC provided. "
		    "automatically detected %02x:%02x:%02x:%02x:%02x:%02x as hw "
		    "interface for %s",
		    zconf.hw_mac[0], zconf.hw_mac[1], zconf.hw_mac[2],
		    zconf.hw_mac[3], zconf.hw_mac[4], zconf.hw_mac[5],
		    zconf.iface);
	}
	log_debug("send", "source MAC address %02x:%02x:%02x:%02x:%02x:%02x",
		  zconf.hw_mac[0], zconf.hw_mac[1], zconf.hw_mac[2],
		  zconf.hw_mac[3], zconf.hw_mac[4], zconf.hw_mac[5]);

	if (zconf.dryrun) {
		log_info("send", "dryrun mode -- won't actually send packets");
	}
	// initialize random validation key
	validate_init();
	// setup signal handlers for changing scan speed
	signal(SIGUSR1, sig_handler_increase_speed);
	signal(SIGUSR2, sig_handler_decrease_speed);
	zsend.start = now();
	return it;
}

static inline ipaddr_n_t get_src_ip(ipaddr_n_t dst, int local_offset)
{
	if (zconf.number_source_ips == 1) {
		return zconf.source_ip_addresses[0];
	}
	return zconf.source_ip_addresses[(ntohl(dst) + local_offset) %
					 zconf.number_source_ips];
}

// one sender thread
int send_run(sock_t st, shard_t *s)
{
	log_debug("send", "send thread started");
	pthread_mutex_lock(&send_mutex);
	// Allocate a buffer to hold the outgoing packet
	char buf[MAX_PACKET_SIZE];
	char buf2[MAX_PACKET_SIZE];
	memset(buf, 0, MAX_PACKET_SIZE);
	memset(buf2, 0, MAX_PACKET_SIZE);

	// OS specific per-thread init
	if (send_run_init(st)) {
		pthread_mutex_unlock(&send_mutex);
		return -1;
	}
	// MAC address length in characters
	char mac_buf[(ETHER_ADDR_LEN * 2) + (ETHER_ADDR_LEN - 1) + 1];
	char *p = mac_buf;
	for (int i = 0; i < ETHER_ADDR_LEN; i++) {
		if (i == ETHER_ADDR_LEN - 1) {
			snprintf(p, 3, "%.2x", zconf.hw_mac[i]);
			p += 2;
		} else {
			snprintf(p, 4, "%.2x:", zconf.hw_mac[i]);
			p += 3;
		}
	}

	char mac_buf2[(ETHER_ADDR_LEN * 2) + (ETHER_ADDR_LEN - 1) + 1];
	*p = mac_buf2;
	for (int i = 0; i < ETHER_ADDR_LEN; i++) {
		if (i == ETHER_ADDR_LEN - 1) {
			snprintf(p, 3, "%.2x", zconf.hw_mac[i]);
			p += 2;
		} else {
			snprintf(p, 4, "%.2x:", zconf.hw_mac[i]);
			p += 3;
		}
	}
	log_debug("send", "source MAC address %s", mac_buf);
	void *probe_data;
	void *probe_data2;
	if (zconf.probe_module->thread_initialize) {
		zconf.probe_module->thread_initialize(
		    buf, zconf.hw_mac, zconf.gw_mac, zconf.target_port,
		    &probe_data);

		zconf.probe_module->thread_initialize2(
		    buf2, zconf.hw_mac, zconf.gw_mac, zconf.target_port,
		    &probe_data2);
	}
	pthread_mutex_unlock(&send_mutex);

	// adaptive timing to hit target rate
	uint64_t count = 0;
	uint64_t last_count = count;
	double last_time = now();
	uint32_t delay = 0;
	int interval = 0;
	volatile int vi;
	struct timespec ts, rem;
	double send_rate =
	    (double)zconf.rate /
	    ((double)zconf.senders * zconf.batch * zconf.packet_streams);
	const double slow_rate = 50; // packets per seconds per thread
	// at which it uses the slow methods
	long nsec_per_sec = 1000 * 1000 * 1000;
	long long sleep_time = nsec_per_sec;
	if (zconf.rate > 0) {
		delay = 10000;
		if (send_rate < slow_rate) {
			// set the initial time difference
			sleep_time = nsec_per_sec / send_rate;
			last_time = now() - (1.0 / send_rate);
		} else {
			// estimate initial rate
			for (vi = delay; vi--;)
				;
			delay *= 1 / (now() - last_time) /
				 ((double)zconf.rate /
				  ((double)zconf.senders * zconf.batch));
			interval = ((double)zconf.rate /
				    ((double)zconf.senders * zconf.batch)) /
				   20;
			last_time = now();
		}
	}
	// Get the initial IP to scan.
	uint32_t current_ip;
	struct in6_addr ipv6_dst;
	
	if (ipv6) {
		ipv6_target_file_get_ipv6(&ipv6_dst);
		probe_data = malloc(2*sizeof(struct in6_addr));
		probe_data2 = malloc(2 * sizeof(struct in6_addr));
	} else {
		current_ip = shard_get_cur_ip(s);

		// If provided a list of IPs to scan, then the first generated address
		// might not be on that list. Iterate until the current IP is one the
		// list, then start the true scanning process.
		if (zconf.list_of_ips_filename) {
			while (!pbm_check(zsend.list_of_ips_pbm, current_ip)) {
				current_ip = shard_get_next_ip(s);
				if (current_ip == ZMAP_SHARD_DONE) {
					log_debug(
						"send",
						"never made it to send loop in send thread %i",
						s->thread_id);
					goto cleanup;
				}
			}
		}
	}
	int attempts = zconf.num_retries + 1;
	uint32_t idx = 0;
	while (1) {
		// Adaptive timing delay
		if (count && delay > 0) {
			if (send_rate < slow_rate) {
				double t = now();
				double last_rate = (1.0 / (t - last_time));

				sleep_time *= ((last_rate / send_rate) + 1) / 2;
				ts.tv_sec = sleep_time / nsec_per_sec;
				ts.tv_nsec = sleep_time % nsec_per_sec;
				log_debug("sleep",
					  "sleep for %d sec, %ld nanoseconds",
					  ts.tv_sec, ts.tv_nsec);
				while (nanosleep(&ts, &rem) == -1) {
				}
				last_time = t;
			} else {
				for (vi = delay; vi--;)
					;
				if (!interval || (count % interval == 0)) {
					double t = now();
					assert(count > last_count);
					assert(t > last_time);
					double multiplier =
					    (double)(count - last_count) /
					    (t - last_time) /
					    (zconf.rate / zconf.senders);
					uint32_t old_delay = delay;
					delay *= multiplier;
					if (delay == old_delay) {
						if (multiplier > 1.0) {
							delay *= 2;
						} else if (multiplier < 1.0) {
							delay *= 0.5;
						}
					}
					last_count = count;
					last_time = t;
				}
			}
		}

		// Check if the program has otherwise completed and break out of the send loop.
		if (zrecv.complete) {
			goto cleanup;
		}
		if (zconf.max_runtime &&
		    zconf.max_runtime <= now() - zsend.start) {
			goto cleanup;
		}

		// Actually send a packet.
		for (int b = 0; b < zconf.batch; b++) {
			// Check if we've finished this shard or thread before sending each
			// packet, regardless of batch size.
			if (s->state.max_hosts &&
			    s->state.hosts_scanned >= s->state.max_hosts) {
				log_debug(
				    "send",
				    "send thread %hhu finished (max targets of %u reached)",
				    s->thread_id, s->state.max_hosts);
				goto cleanup;
			}
			if (s->state.max_packets &&
			    s->state.packets_sent >= s->state.max_packets) {
				log_debug(
				    "send",
				    "send thread %hhu finished (max packets of %u reached)",
				    s->thread_id, s->state.max_packets);
				goto cleanup;
			}
			if (!ipv6 && current_ip == ZMAP_SHARD_DONE) {
				log_debug(
				    "send",
				    "send thread %hhu finished, shard depleted",
				    s->thread_id);
				goto cleanup;
			}
			for (int i = 0; i < zconf.packet_streams; i++) {
				count++;
				uint32_t src_ip = get_src_ip(current_ip, i);
				uint32_t validation[VALIDATE_BYTES /
						    sizeof(uint32_t)];
				// IPv6
				if (ipv6) {
					((struct in6_addr *) probe_data)[0] = ipv6_src;
					((struct in6_addr *) probe_data)[1] = ipv6_dst;

					((struct in6_addr *) probe_data2)[0] = ipv6_src;
					((struct in6_addr *) probe_data2)[1] = ipv6_dst;
					validate_gen_ipv6(&ipv6_src, &ipv6_dst, (uint8_t *)validation);
				} else {
					validate_gen(src_ip, current_ip,
						     (uint8_t *)validation);
				}
				uint8_t ttl = zconf.probe_ttl;
				size_t length = 0;
				
				zconf.probe_module->make_packet(
				    buf, &length, src_ip, current_ip, ttl,
				    validation, i, probe_data);

				size_t length2 = zconf.probe_module->max_packet2_length;
				zconf.probe_module->make_packet2(
				    buf2, &length2, src_ip, current_ip, ttl,
				    validation, i, probe_data2);

				if (length > MAX_PACKET_SIZE) {
					log_fatal(
					    "send",
					    "send thread %hhu set length (%zu) larger than MAX (%zu)",
					    s->thread_id, length,
					    MAX_PACKET_SIZE);
				}
				if (zconf.dryrun) {
					lock_file(stdout);
					zconf.probe_module->print_packet(stdout,
									 buf);
					zconf.probe_module->print_packet(stdout,
									 buf2);
					unlock_file(stdout);
				} else {
					void *contents = buf + zconf.send_ip_pkts * sizeof(struct ether_header);
					length -= (zconf.send_ip_pkts * sizeof(struct ether_header));

					void *contents2 = buf2 + zconf.send_ip_pkts * sizeof(struct ether_header);
					length2 -= (zconf.send_ip_pkts * sizeof(struct ether_header));

					int any_sends_successful = 0;
					for (int i = 0; i < attempts; ++i) {
						
						int rc = send_packet(st, contents, length, idx);
						if (rc < 0) {
							// IPv6
							if (ipv6) {
								char ipv6_str[100];
								inet_ntop(AF_INET6, &ipv6_dst, ipv6_str, 100-1);
								log_debug("send", "send_packet failed for %s. %s",
										  ipv6_str, strerror(errno));
							} else {
								struct in_addr addr;
								addr.s_addr = current_ip;
								char addr_str_buf[INET_ADDRSTRLEN];
								const char *addr_str =
								    inet_ntop(
									AF_INET, &addr,
									addr_str_buf,
									INET_ADDRSTRLEN);
								if (addr_str != NULL) {
									log_debug(
									"send",
									"send_packet failed for %s. %s",
									addr_str,
									strerror(
										errno));
								}
							}
						}
						idx++;
						int rc2 = send_packet(st, contents2, length2, idx);
						
						if (rc2 < 0) {
							// IPv6
							if (ipv6) {
								char ipv6_str[100];
								inet_ntop(AF_INET6, &ipv6_dst, ipv6_str, 100-1);
								log_debug("send", "send_packet failed for %s. %s",
										  ipv6_str, strerror(errno));
							} else {
								struct in_addr addr2;
								addr2.s_addr = current_ip;
								char addr_str_buf2[INET_ADDRSTRLEN];
								const char *addr_str2 =
								    inet_ntop(
									AF_INET, &addr2,
									addr_str_buf2,
									INET_ADDRSTRLEN);
								if (addr_str2 != NULL) {
									log_debug(
									"send",
									"send_packet failed for %s. %s",
									addr_str2,
									strerror(
										errno));
								}
							}
						} 
						
						if(rc >= 0 && rc2 >= 0){
							any_sends_successful =1;
							break;
						}
					}
					if (!any_sends_successful) {
						s->state.packets_failed++;
					}
					idx++;
					idx &= 0xFF;
				}
				s->state.packets_sent++;
				
			}
			// Track the number of hosts we actually scanned.
			s->state.hosts_scanned++;

			// IPv6
			if (ipv6) {
				int ret = ipv6_target_file_get_ipv6(&ipv6_dst);
				if (ret != 0) {
					log_debug("send", "send thread %hhu finished, no more target IPv6 addresses", s->thread_id);
					goto cleanup;
				}
			} else {
				// Get the next IP to scan
				current_ip = shard_get_next_ip(s);
				if (zconf.list_of_ips_filename &&
				    current_ip != ZMAP_SHARD_DONE) {
					// If we have a list of IPs bitmap, ensure the next IP
					// to scan is on the list.
					while (!pbm_check(zsend.list_of_ips_pbm,
						  current_ip)) {
						current_ip = shard_get_next_ip(s);
						if (current_ip == ZMAP_SHARD_DONE) {
							log_debug(
							"send",
							"send thread %hhu shard finished in get_next_ip_loop depleted",
							s->thread_id);
							goto cleanup;
						}
					}
				}
			}
		}
	}
cleanup:
	s->cb(s->thread_id, s->arg);
	if (zconf.dryrun) {
		lock_file(stdout);
		fflush(stdout);
		unlock_file(stdout);
	}
	log_debug("send", "thread %hu cleanly finished", s->thread_id);
	return EXIT_SUCCESS;
}
