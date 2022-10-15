/**
 * @file capture.cpp
 * @author xzvara01 (xzvara01@stud.fit.vutbr.cz)
 * @brief Capturing incoming traffic with libpcap
 * @date 2022-10-06
 *
 */

#include <iostream>
#include <string>

#include "capture.hpp"

#define IP_MINLEN  20
#define TCP_MINLEN 20
#define UDP_LEN 8
#define ICMP_LEN 8

Capture::~Capture()
{
    if (handle != NULL) {
        pcap_freecode(&fp);
        pcap_close(handle);
    }
}

void Capture::open(FILE* file)
{
    // open pcap file (or read from stdin)
    handle = pcap_fopen_offline(file, errbuf);
    if (handle == NULL) {
        throw std::runtime_error(errbuf);
    }
}

void Capture::apply_filter(const char* filter_expr)
{
    // compile and apply filter
	if (pcap_compile(handle, &fp, filter_expr, 0, 0) == -1) {
        std::string msg("Couldn't parse filter \"");
        msg.append(filter_expr);
        msg.append("\"");
        throw std::invalid_argument(msg);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
        std::string msg("Couldn't install filter \"");
        msg.append(filter_expr);
        msg.append("\"");
        throw std::runtime_error(msg);
	}
}

int Capture::next_packet()
{
    int err;

    // reading packet
    if ((err = pcap_next_ex(handle, &header, &packet)) < 0) {
        return err;
    }

    // check if we are capturing ethernet
    if (pcap_datalink(handle) != DLT_EN10MB) {
        return ERR_NONETH;
    }

    /* parsing ethernet header */
    // check if eth header is long enough so that we dont access invalid memory
    if (header->len < ETH_HLEN) {
        return ERR_INCOMPLETE;
    }

    /* parsing ip header */
    // check if ip header is long enough so that we dont access invalid memory
    ip_header = (iphdr *)(packet + ETH_HLEN);
    if (header->len - ETH_HLEN < IP_MINLEN) {
        return ERR_INCOMPLETE;
    }

    // remaining of the header is transport layer protocol - check for each protocol if they are complete
    int ip_hlen = (ip_header->ihl & 0xf) * 4;
    if (ip_header->protocol == IPPROTO_TCP) {
        if (header->len - ETH_HLEN - ip_hlen < TCP_MINLEN) {
            return ERR_INCOMPLETE;
        }
    } else if (ip_header->protocol == IPPROTO_UDP) {
        if (header->len - ETH_HLEN - ip_hlen < UDP_LEN) {
            return ERR_INCOMPLETE;
        }
    } else { // ICMP header
        if (header->len - ETH_HLEN - ip_hlen < ICMP_LEN) {
            return ERR_INCOMPLETE;
        }
    }

    transport_header = (void *)(packet + ETH_HLEN + ip_hlen);

    return 0;
}