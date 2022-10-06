/**
 * @file store.cpp
 * @author xzvara01 (xzvara01@stud.fit.vutbr.cz)
 * @brief Module for storing flows created by the program
 * @date 2022-10-06
 *
 */

#include <netinet/tcp.h>     // struct tcphdr
#include <netinet/udp.h>     // struct udphdr

#include "store.hpp"
#include "debug.hpp"

#define ETH_HLEN 14

uint64_t FlowSeq;   // last sequence number used in header

void make_header(netflowV5H& header, int count)
{
    header.version = htons(5);
    header.count = htons(count);
    header.SysUpTime = htons(SysUpTime - LastTime);
    header.unix_secs = htons(SysUpTime + LastTime);
    header.unix_nsecs = 0;
    header.flow_sequence = htons(FlowSeq);
    FlowSeq += count;
}

void flow_insert(Capture& cap, flowc_t& flow_cache)
{
    uint16_t Sportn, Dportn;
    netkey_t key;
    get_ports(cap, Sportn, Dportn);
    key = std::make_tuple(cap.ip_header->saddr, cap.ip_header->daddr, Sportn, Dportn, cap.ip_header->protocol);

    auto search = flow_cache.find(key);
    if (search != flow_cache.end()) {
        // flow already exists in cache
        update_flow(cap, search->second);
        // debug print
        dfprintf(DEBUG_STRING, search->second.srcaddr, search->second.dstaddr, search->second.srcport, search->second.dstport,\
            search->second.prot, search->second.First, search->second.Last, search->second.dOctets, search->second.dPkts);
    } else {
        // flow does not exist in cache
        netflowV5R flow {};
        create_flow(cap, flow, Sportn, Dportn);
        flow_cache.insert({key, flow});
        // debug print
        dfprintf(DEBUG_STRING,flow.srcaddr,flow.dstaddr,flow.srcport, flow.dstport, flow.prot,flow.First,flow.Last,flow.dOctets,flow.dPkts);
    }
}

void update_flow(Capture &cap, netflowV5R& flow)
{
    tcphdr *hdr = (tcphdr *)cap.transport_header;

    flow.dPkts = flow.dPkts + htonl(1);
    flow.dOctets = flow.dOctets + htonl(cap.header->len - ETH_HLEN);
    flow.Last = get_packet_timestamp(cap);
    flow.tcp_flags = flow.tcp_flags | (flow.prot == IPPROTO_TCP ? hdr->th_flags : 0);
}

void create_flow(Capture &cap, netflowV5R& flow, uint16_t Sportn, uint16_t Dportn)
{
    tcphdr *hdr = (tcphdr *)cap.transport_header;

    if (SysUpTime == 0) {
        SysUpTime = (cap.header->ts.tv_sec * 1000) + (cap.header->ts.tv_usec / 1000);
        LastTime = SysUpTime;
    }

    flow.srcaddr = cap.ip_header->saddr;
    flow.dstaddr = cap.ip_header->daddr;
    flow.dPkts = htonl(1);
    flow.dOctets = htonl(cap.header->len - ETH_HLEN);
    flow.First = get_packet_timestamp(cap);
    flow.Last = flow.First;
    flow.srcport = Sportn;
    flow.dstport = Dportn;
    flow.tcp_flags = cap.ip_header->protocol == IPPROTO_TCP ? hdr->th_flags : 0;
    flow.prot = cap.ip_header->protocol;
    flow.tos = cap.ip_header->tos;
}

void get_ports(Capture& cap, uint16_t& Sportn, uint16_t& Dportn)
{
    uint16_t proto = cap.ip_header->protocol;
    if (proto == IPPROTO_TCP) {
        tcphdr *hdr = (tcphdr *)cap.transport_header;
        Sportn = hdr->th_sport;
        Dportn = hdr->th_dport;
    } else if (proto == IPPROTO_UDP) {
        udphdr *hdr = (udphdr *)cap.transport_header;
        Sportn = hdr->uh_sport;
        Dportn = hdr->uh_dport;
    } else {
        Sportn = Dportn = 0;
    }
}

bool time_second_passed(time_t sec, suseconds_t usec)
{
    sec *= 1000;
    usec /= 1000;
    if ((sec + usec - LastTime) >= 1000) {
        LastTime = sec + usec;
        return true;
    }
    return false;
}

int get_packet_timestamp(Capture &cap)
{
    return (cap.header->ts.tv_sec * 1000) + (cap.header->ts.tv_usec / 1000)  - SysUpTime;
}