/**
 * @file flow.cpp
 * @author xzvara01 (xzvara01@stud.fit.vutbr.cz)
 * @brief Main program for exporting captured data to collector
 * @date 2022-10-06
 *
 */

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>     // sockaddr_in
#include <unistd.h>         // close
#include <algorithm>        // sort

#include "flow.hpp"
#include "src/capture.hpp"
#include "src/debug.hpp"
#include "src/store.hpp"

uint64_t SysUpTime;     // save system uptime from first captured packet (in miliseconds)
timeval LastChecked;    // store last time we checked flow_cache for records to export (in miliseconds)

void sendUdp(const char *data, const size_t size, sockaddr_storage& address, const uint16_t port)
{
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

    if (sendto(socket_fd, data, size, 0, (struct sockaddr*)&address, addrlen) == -1) {
        throw std::runtime_error("Sendto failed");
    };
}

char *prepare_structs(std::vector<netflowV5R> flows, size_t& buff_size)
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

void export_single(const Capture& cap, flowc_t& flow_cache, arguments& args)
{
    netflowV5R record;
    fcache_find(cap, flow_cache, &record);

    std::vector<netflowV5R> flows_to_export;
    flows_to_export.push_back(record);
    size_t buff_size;
    char *buffer = prepare_structs(flows_to_export, buff_size);
    sendUdp(buffer, buff_size, args.address, args.port);
}

void export_oldest(flowc_t& flow_cache, arguments& args)
{
    flowc_t::const_iterator to_delete;
    uint32_t oldest_time = UINT32_MAX;
    for (auto record = flow_cache.cbegin(); record != flow_cache.cend(); ++record) {
        if (ntohl(record->second.First) < oldest_time) {
            to_delete = record;
            oldest_time = ntohl(record->second.First);
        }
    }

    flow_cache.erase(to_delete);
    std::vector<netflowV5R> flows_to_export;
    flows_to_export.push_back(to_delete->second);
    size_t buff_size;
    char *buffer = prepare_structs(flows_to_export, buff_size);
    sendUdp(buffer, buff_size, args.address, args.port);
    dfcprintf();
}

bool sortingFunction(netflowV5R r1, netflowV5R r2) {
    return (ntohl(r1.First) < ntohl(r2.First));
}

void export_flows(flowc_t& flow_cache, arguments& args)
{
    std::vector<netflowV5R> flows_to_export;
    int counter = 0;

    while (true) {
        for (auto record = flow_cache.cbegin(); record != flow_cache.cend();) {
            if (counter == 30) {
                break;
            }
            // check for inactive timer
            if (LastChecked.tv_sec*1000+LastChecked.tv_usec/1000 - SysUpTime - ntohl(record->second.Last) > args.inactive * 1000) {
                // debug print
                deprintf("Inactive timeout ran out: ");
                dexprintf();

                flows_to_export.push_back(record->second); // store flows to be exported
                flow_cache.erase(record++); // removing items from map while iterating workaround
                counter++;
                continue;
            }

            // check for active timer
            if (ntohl(record->second.Last) - ntohl(record->second.First) > args.active * 1000) {
                // debug print
                deprintf("Active timeout ran out: ");
                dexprintf();

                flows_to_export.push_back(record->second); // store flows to be exported
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
        std::sort(flows_to_export.begin(), flows_to_export.end(), sortingFunction);

        size_t buff_size;
        char *buffer = prepare_structs(flows_to_export, buff_size);
        sendUdp(buffer, buff_size, args.address, args.port);

        if (counter < 30) {
            break;
        }

        counter = 0;
    }

}

void clear_cache(flowc_t& flow_cache, arguments& args)
{
    std::vector<netflowV5R> flows_to_export;

    while (!flow_cache.empty()) {
        int counter = 0;
        for (auto record = flow_cache.cbegin(); record != flow_cache.cend();) {
            flows_to_export.push_back(record->second); // store flows to be exported
            flow_cache.erase(record++); // removing items from map while iterating
            if (++counter == 30) {
                counter = 0;
                break;
            }
        }

    // sort flows by time
    std::sort(flows_to_export.begin(), flows_to_export.end(), sortingFunction);

    size_t buff_size;
    char *buffer = prepare_structs(flows_to_export, buff_size);
    sendUdp(buffer, buff_size, args.address, args.port);

    flows_to_export.clear();
    }
}

int main(int argc, char **argv)
{
    arguments args {}; // argument structure
    Capture cap {};    // pcap structure for capturing packets
    const char *filter_expr = "ip proto 1 or ip proto 6 or ip proto 17"; // pcap filter expression

    flowc_t flow_cache; // storage of flows

    try {
        parse_arguments(argc, argv, args);
        cap.open(args.pcapfile);
        cap.apply_filter(filter_expr);
    } catch(const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << '\n';
        if (args.pcapfile != NULL) {
            fclose(args.pcapfile);
        }
        return 1;
    }

    int ret;

    while (true) {
        // capture packet
        ret = cap.next_packet();
        // first check for my own defined errors (incomplete header or not ethernet header)
        if (ret == ERR_INCOMPLETE || ret == ERR_NONETH) {
            // in these cases we can skip these packets and continue
            std::cerr << "Skipped packet\n";
            continue;
        } else if (ret < 0) {
            // check if any error occured
            if (ret != PCAP_ERROR_BREAK) {
                std::cerr << "ERROR: pcap_next_ex failed\n";
                return 1;
            }
            break;
        }


        /** 1 second has not passed, collect more packets */
        // if (!time_second_passed(cap.header->ts.tv_sec, cap.header->ts.tv_usec)){
        //     continue;
        // }

        /** variant for exporting after each packet is recieved */
        LastChecked.tv_sec = cap.header->ts.tv_sec;
        LastChecked.tv_usec = cap.header->ts.tv_usec;

        try {
            // catching allocation exceptions
            export_flows(flow_cache, args); // export flows from flow cache to collector
        } catch(const std::exception& e) {
            std::cerr << e.what() << '\n';
            return 1;
        }


        ret = flow_insert(cap, flow_cache, args.cache_size); // insert flow to flow cache
        if (ret < 0) {
            // flow cache is full, export oldest flow
            try {
                export_oldest(flow_cache, args);
            } catch(const std::exception& e) {
                std::cerr << e.what() << '\n';
                return 1;
            }
            flow_insert(cap, flow_cache, args.cache_size);
        }

        if (tcp_rstfin(cap)) {
            export_single(cap, flow_cache, args);
        }
    }

    dfcprintf(); // print out flow cache for debugging purposes

    clear_cache(flow_cache, args);

    return 0;
}