/**
 * @file flow.cpp
 * @author xzvara01 (xzvara01@stud.fit.vutbr.cz)
 * @brief TODO:
 * @date 2022-10-03
 *
 */

#include <iostream>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>      // sockaddr_in

#include "flow.hpp"
#include "src/store.hpp"
#include "src/capture.hpp"
#include "src/parse.hpp"
#include "src/debug.hpp"

uint64_t SysUpTime; // save system uptime from first captured packet
uint64_t LastTime;  // store last time we checked flow_cache for records to export

void sendUdp(const char *data, size_t size, arguments& args)
{
    int socket_fd = args.address.ss_family == AF_INET ?
                    socket(AF_INET, SOCK_DGRAM, 0)    :
                    socket(AF_INET6, SOCK_DGRAM, 0);
    if (socket_fd == -1) {
        return;
    }

    socklen_t addrlen = args.address.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

    if (args.address.ss_family == AF_INET) {
        ((sockaddr_in *)&args.address)->sin_port = htons(args.port);
    } else {
        ((sockaddr_in6 *)&args.address)->sin6_port = htons(args.port);
    }

    if (sendto(socket_fd, data, size, 0, (struct sockaddr*)&args.address, addrlen) == -1) {
        perror("sendto: ");
    };
}

void export_flows(flowc_t& flow_cache, arguments& args)
{
    std::vector<netflowV5R> flows_to_export;

    for (auto record = flow_cache.cbegin(); record != flow_cache.cend();) {
        // check for inactive timer
        if (LastTime - SysUpTime - record->second.Last > args.inactive * 1000) {
            dfprintf("Inactive timeout ran out: ");
            dsfprintf();
            flows_to_export.push_back(record->second); // store flows to be exported
            flow_cache.erase(record++); // removing items from map while iterating workaround
            continue;
        }

        // check for active timer
        if (record->second.Last - record->second.First > args.active * 1000) {
            dfprintf("Active timeout ran out: ");
            dsfprintf();
            flows_to_export.push_back(record->second); // store flows to be exported
            flow_cache.erase(record++);
            continue;
        }

        ++record; // removing items from map while iterating workaroundf
    }

    if (flows_to_export.empty()) {
        return;
    }

    netflowV5H header {};
    make_header(header, flows_to_export.size());

    size_t buff_size = sizeof(header) + flows_to_export.size() * sizeof(netflowV5R);
    char *buffer = new char[buff_size];
    memset(buffer, 0, buff_size);
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer+sizeof(header), flows_to_export.data(), buff_size - sizeof(header));
    sendUdp(buffer, buff_size, args);
}

void clear_cache(flowc_t& flow_cache, arguments& args)
{
    std::vector<netflowV5R> flows_to_export;

    while (!flow_cache.empty()) {
        int counter = 0;
        for (auto record = flow_cache.cbegin(); record != flow_cache.cend();) {
            flows_to_export.push_back(record->second); // store flows to be exported
            flow_cache.erase(record++); // removing items from map while iterating workaround
            if (++counter == 30) {
                counter = 0;
                break;
            }
        }

        netflowV5H header {};
        make_header(header, flows_to_export.size());

        size_t buff_size = sizeof(header) + flows_to_export.size() * sizeof(netflowV5R);
        char *buffer = new char[buff_size];
        memset(buffer, 0, buff_size);
        memcpy(buffer, &header, sizeof(header));
        memcpy(buffer+sizeof(header), flows_to_export.data(), buff_size - sizeof(header));
        sendUdp(buffer, buff_size, args);

        flows_to_export.clear();
    }
}

int main(int argc, char **argv)
{
    arguments args; // argument structure
    Capture cap; // pcap structure for capturing packets
    const char *filter_expr = "ip proto 1 or ip proto 6 or ip proto 17"; // pcap filter expression

    flowc_t flow_cache; // storage of flows

    try {
        parse_arguments(argc, argv, args);
        cap.open(args.pcapfile);
        cap.apply_filter(filter_expr);
    } catch(const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << '\n';
        return 1;
    }

    int ret;

    try {
        while ((ret = cap.next_packet()) >= 0) {
            flow_insert(cap, flow_cache);
            if (time_second_passed(cap.header->ts.tv_sec, cap.header->ts.tv_usec)){
                export_flows(flow_cache, args);
            }
        }
    } catch(const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << '\n';
    }

    if (ret == PCAP_ERROR) {
        std::cerr << "ERROR: pcap_next_ex failed\n";
        return 1;
    }

    dfcprintf(); // print out flow cache for debugging purposes

    clear_cache(flow_cache, args);

    return 0;
}