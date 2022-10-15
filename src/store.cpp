/**
 * @file store.cpp
 * @author xzvara01 (xzvara01@stud.fit.vutbr.cz)
 * @brief Module for storing flows created by the program
 * @date 2022-10-06
 *
 */

#include <netinet/tcp.h>     // struct tcphdr
#include <netinet/udp.h>     // struct udphdr
#include <algorithm>         // find

#include "store.hpp"
#include "debug.hpp"

uint64_t FlowSeq;   // last sequence number used in header

inline int get_packet_timestamp(const pcap_pkthdr *hdr)
{
    return (hdr->ts.tv_sec * 1000) + (hdr->ts.tv_usec / 1000)  - SysUpTime;
}

inline int get_timestamp_miliseconds(const timeval *time)
{
    return (time->tv_sec * 1000) + (time->tv_usec / 1000);
}

bool time_second_passed(const time_t sec, const suseconds_t usec)
{
    auto _sec = sec * 1000;
    auto _usec = usec / 1000;
    if ((_sec + _usec - get_timestamp_miliseconds(&LastChecked)) >= EXPORT_TIMER) {
        LastChecked.tv_sec = _sec;
        LastChecked.tv_usec = _usec;
        return true;
    }
    return false;
}

void fcache_find(const Capture& cap, flowc_t& flow_cache, netflowV5R *record)
{
    uint16_t Sportn, Dportn;
    netkey_t key;
    get_ports(cap, Sportn, Dportn);
    key = std::make_tuple(cap.ip_header->saddr, cap.ip_header->daddr, Sportn, Dportn, cap.ip_header->protocol);
    *record = flow_cache.at(key);
    flow_cache.erase(key);
}

bool tcp_rstfin(const Capture& cap)
{
    tcphdr *hdr;
    if (cap.ip_header->protocol == IPPROTO_TCP) {
        hdr = (tcphdr *)cap.transport_header;
        if (hdr->th_flags & TH_FIN || hdr->th_flags == TH_RST) {
            return true;
        }
    }
    return false;
}

void fill_header(netflowV5H& header, const int count)
{
    header.version = htons(5);
    header.count = htons(count);
    header.SysUpTime = htonl(get_timestamp_miliseconds(&LastChecked) - SysUpTime);
    header.unix_secs = htonl(LastChecked.tv_sec);
    header.unix_nsecs = htonl(LastChecked.tv_usec*1000);
    header.flow_sequence = htonl(FlowSeq);
    FlowSeq += count;
}

void get_ports(const Capture& cap, uint16_t& Sportn, uint16_t& Dportn)
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
        Sportn = Dportn = 0; // ICMP has no port
    }
}

void update_flow(const Capture &cap, netflowV5R& flow)
{
    tcphdr *hdr = (tcphdr *)cap.transport_header;

    flow.dPkts = htonl(ntohl(flow.dPkts) + 1);
    flow.dOctets = htonl(ntohl(flow.dOctets) + cap.header->len - ETH_HLEN);
    flow.Last = htonl(get_packet_timestamp(cap.header));
    flow.tcp_flags |= (flow.prot == IPPROTO_TCP ? hdr->th_flags : 0);
}

void create_flow(const Capture &cap, netflowV5R& flow, const uint16_t Sportn, const uint16_t Dportn)
{
    tcphdr *hdr = (tcphdr *)cap.transport_header;

    // if it is the first packet ever recieved, set SysUptime
    if (SysUpTime == 0) {
        SysUpTime = (cap.header->ts.tv_sec * 1000) + (cap.header->ts.tv_usec / 1000);
        //LastChecked = SysUpTime;
    }

    flow.srcaddr = cap.ip_header->saddr;
    flow.dstaddr = cap.ip_header->daddr;
    flow.dPkts = htonl(1);
    flow.dOctets = htonl(cap.header->len - ETH_HLEN);
    flow.First = htonl(get_packet_timestamp(cap.header));
    flow.Last = flow.First;
    flow.srcport = Sportn;
    flow.dstport = Dportn;
    flow.tcp_flags = cap.ip_header->protocol == IPPROTO_TCP ? hdr->th_flags : 0;
    flow.prot = cap.ip_header->protocol;
    flow.tos = cap.ip_header->tos;
}

int flow_insert(const Capture& cap, flowc_t& flow_cache, uint64_t flowsize)
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
        diuprintf(search->second.srcaddr, search->second.dstaddr, search->second.srcport, search->second.dstport,\
            search->second.prot, search->second.First, search->second.Last, search->second.dOctets, search->second.dPkts);
    } else {
        // flow does not exist in cache
        // check if flow cache has enough space for new record
        if (flow_cache.size() == flowsize) {
            return FCACHE_FULL;
        }

        netflowV5R flow {};
        create_flow(cap, flow, Sportn, Dportn);
        flow_cache.insert({key, flow});

        // debug print
        dicprintf(flow.srcaddr,flow.dstaddr,flow.srcport, flow.dstport, flow.prot,flow.First,flow.Last,flow.dOctets,flow.dPkts);
    }

    return 0;
}