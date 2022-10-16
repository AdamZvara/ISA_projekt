/**
 * @file store.cpp
 * @author xzvara01 (xzvara01@stud.fit.vutbr.cz)
 * @brief Module for storing flows created by the program
 * @date 2022-10-16
 *
 */

#include <netinet/tcp.h>     // struct tcphdr
#include <netinet/udp.h>     // struct udphdr
#include <algorithm>         // find

#include "store.hpp"
#include "debug.hpp"

uint64_t FlowSeq;   // last sequence number used in header

/** Private functions               */

inline int get_timestamp_miliseconds(const timeval time)
{
    return (time.tv_sec * 1000) + (time.tv_usec / 1000);
}

inline bool sortingFunction(netflowV5R r1, netflowV5R r2) {
    return (ntohl(r1.First) < ntohl(r2.First));
}

void Store::create_flow(const Capture &cap, NetFlowRecord& flow, const uint16_t Sportn, const uint16_t Dportn)
{
    // !! only access if packet contained TCP header !!
    tcphdr *hdr = (tcphdr *)cap.transport_header;

    // if it is the first packet ever recieved, set SysUptime
    if (SysUpTime == 0) {
        SysUpTime = (cap.header->ts.tv_sec * 1000) + (cap.header->ts.tv_usec / 1000);
    }

    flow.rec.srcaddr = cap.ip_header->saddr;
    flow.rec.dstaddr = cap.ip_header->daddr;
    flow.rec.dPkts = htonl(1);
    flow.rec.dOctets = htonl(cap.header->len - ETH_HLEN);
    flow.rec.First = htonl(cap.get_packet_timestamp());
    flow.rec.Last = flow.rec.First;
    flow.rec.srcport = Sportn;
    flow.rec.dstport = Dportn;
    flow.rec.tcp_flags = cap.ip_header->protocol == IPPROTO_TCP ? hdr->th_flags : 0;
    flow.rec.prot = cap.ip_header->protocol;
    flow.rec.tos = cap.ip_header->tos;
    flow.lastFlag = cap.ip_header->protocol == IPPROTO_TCP ? hdr->th_flags : 0;
}

void Store::update_flow(const Capture &cap, NetFlowRecord& flow)
{
    // !! only access if packet contained TCP header !!
    tcphdr *hdr = (tcphdr *)cap.transport_header;

    flow.rec.dPkts = htonl(ntohl(flow.rec.dPkts) + 1);
    flow.rec.dOctets = htonl(ntohl(flow.rec.dOctets) + cap.header->len - ETH_HLEN);
    flow.rec.Last = htonl(cap.get_packet_timestamp());
    flow.rec.tcp_flags |= (flow.rec.prot == IPPROTO_TCP ? hdr->th_flags : 0);

    flow.lastFlag = flow.rec.prot == IPPROTO_TCP ? hdr->th_flags : 0;
}

int Store::find_flow(const Capture& cap, netflowV5R *record)
{
    uint16_t Sportn, Dportn;
    netkey_t key;
    cap.get_ports(Sportn, Dportn);
    key = std::make_tuple(cap.ip_header->saddr, cap.ip_header->daddr, Sportn, Dportn, cap.ip_header->protocol);
    try {
        *record = flow_cache.at(key).rec;
    } catch(const std::exception& e) {
        return -1;
    }

    flow_cache.erase(key);
    return 0;
}

void Store::export_oldest(arguments args)
{
    /** Finding record with oldest 'First' timestamp */
    flowc_t::const_iterator to_delete;
    uint32_t oldest_time = UINT32_MAX;
    for (auto record = flow_cache.cbegin(); record != flow_cache.cend(); ++record) {
        uint32_t convertedTime = ntohl(record->second.rec.First);
        if (convertedTime < oldest_time) {
            to_delete = record;
            oldest_time = convertedTime;
        }
    }

    /** Erase record from cache and export it */
    flow_cache.erase(to_delete);
    std::vector<netflowV5R> flows_to_export;
    flows_to_export.push_back(to_delete->second.rec);
    send_udp(flows_to_export, args.address, args.port);
    dfcprintf();
}

/** Public functions                */

int Store::insert(const Capture& cap, arguments args)
{
    uint16_t Sportn, Dportn;
    netkey_t key;
    cap.get_ports(Sportn, Dportn);
    key = std::make_tuple(cap.ip_header->saddr, cap.ip_header->daddr, Sportn, Dportn, cap.ip_header->protocol);

    auto search = flow_cache.find(key);
    if (search != flow_cache.end()) {
        // flow already exists in cache
        update_flow(cap, search->second);

         // check for TCP termination based on flags
        if (cap.tcp_fin() && (search->second.lastFlag & TH_ACK)) {
            export_single(cap, args);
        } else if (cap.tcp_ack() && (search->second.lastFlag & TH_FIN)) {
            export_single(cap, args);
        }

        // debug print
        diuprintf(search->second.srcaddr, search->second.dstaddr, search->second.srcport, search->second.dstport,\
            search->second.prot, search->second.First, search->second.Last, search->second.dOctets, search->second.dPkts);
    } else {
        // flow does not exist in cache
        // check if flow cache has enough space for new record
        if (flow_cache.size() == args.cache_size) {
            export_oldest(args);
        }

        NetFlowRecord flow {};
        create_flow(cap, flow, Sportn, Dportn);
        flow_cache.insert({key, flow});

        // debug print
        dicprintf(flow.srcaddr,flow.dstaddr,flow.srcport, flow.dstport, flow.prot,flow.First,flow.Last,flow.dOctets,flow.dPkts);
    }

    return 0;
}

void Store::fexport(arguments args)
{
    std::vector<netflowV5R> flows_to_export;
    int counter = 0;

    // iterate multiple times since flows can only be exported in batches of 30
    while (true) {
        // iterate through flow cache
        for (auto record = flow_cache.cbegin(); record != flow_cache.cend();) {

            if (counter == 30) {
                break; // for loop
            }

            // check for inactive timer
            if (LastChecked.tv_sec*1000+LastChecked.tv_usec/1000 - SysUpTime - ntohl(record->second.rec.Last) > args.inactive * 1000) {
                // debug print
                deprintf("Inactive timeout ran out: ");
                dexprintf();

                flows_to_export.push_back(record->second.rec); // store flows to be exported
                flow_cache.erase(record++); // removing items from map while iterating workaround
                counter++;
                continue;
            }

            // check for active timer
            if (ntohl(record->second.rec.Last) - ntohl(record->second.rec.First) > args.active * 1000) {
                // debug print
                deprintf("Active timeout ran out: ");
                dexprintf();

                flows_to_export.push_back(record->second.rec); // store flows to be exported
                flow_cache.erase(record++);
                counter++;
                continue;
            }

            ++record; // removing items from map while iterating workaround
        }

        if (flows_to_export.empty()) {
            return;
        }

        // sort flows by starting time
        // std::sort(flows_to_export.begin(), flows_to_export.end(), sortingFunction);

        send_udp(flows_to_export, args.address, args.port);

        // stop while loop if this is the last batch of flows to export
        if (counter < 30) {
            break;
        }

        counter = 0;
    } // while
}

void Store::export_single(const Capture& cap, arguments args)
{
    netflowV5R record;
    if (find_flow(cap, &record) < 0) {
        return;
    }

    std::vector<netflowV5R> flows_to_export;
    flows_to_export.push_back(record);
    send_udp(flows_to_export, args.address, args.port);
}

void Store::clear(arguments args)
{
    std::vector<netflowV5R> flows_to_export;

    while (!flow_cache.empty()) {
        int counter = 0;
        for (auto record = flow_cache.cbegin(); record != flow_cache.cend();) {
            flows_to_export.push_back(record->second.rec); // store flows to be exported
            flow_cache.erase(record++); // removing items from map while iterating
            if (++counter == 30) {
                counter = 0;
                break;
            }
        }

    // sort flows by time
    //std::sort(flows_to_export.begin(), flows_to_export.end(), sortingFunction);

    send_udp(flows_to_export, args.address, args.port);

    flows_to_export.clear();
    }
}

void fill_header(netflowV5H& header, const int count)
{
    header.version = htons(5);
    header.count = htons(count);
    header.SysUpTime = htonl(get_timestamp_miliseconds(LastChecked) - SysUpTime);
    header.unix_secs = htonl(LastChecked.tv_sec);
    header.unix_nsecs = htonl(LastChecked.tv_usec*1000);
    header.flow_sequence = htonl(FlowSeq);
    FlowSeq += count;
}

char *prepare_export(std::vector<netflowV5R> flows, size_t& buff_size)
{
    netflowV5H header {};
    fill_header(header, flows.size());

    buff_size = sizeof(header) + flows.size() * sizeof(netflowV5R);
    char *buffer = new char[buff_size];
    memset(buffer, 0, buff_size);
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer+sizeof(header), flows.data(), buff_size - sizeof(header));

    return buffer;
}

void send_udp(std::vector<netflowV5R> flows, sockaddr_storage& address, const uint16_t port)
{
    size_t buff_size;
    char *buffer = prepare_export(flows, buff_size);

    // create socket based on address family
    int socket_fd = address.ss_family == AF_INET ?
                    socket(AF_INET, SOCK_DGRAM, 0)    :
                    socket(AF_INET6, SOCK_DGRAM, 0);
    if (socket_fd == -1) {
        throw std::runtime_error("Socket could not be created");
    }

    socklen_t addrlen = address.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    // set port based on version of IP address
    if (address.ss_family == AF_INET) {
        ((sockaddr_in *)&address)->sin_port = htons(port);
    } else {
        ((sockaddr_in6 *)&address)->sin6_port = htons(port);
    }

    if (sendto(socket_fd, buffer, buff_size, 0, (struct sockaddr*)&address, addrlen) == -1) {
        throw std::runtime_error("Sendto failed");
    };
}