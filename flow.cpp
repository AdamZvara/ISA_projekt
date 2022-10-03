/**
 * @file flow.cpp
 * @author xzvara01, xzvara01@stud.fit.vutbr.cz
 * @brief TODO:
 * @date September 2022
 */

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <netinet/if_ether.h>

#include "flow.hpp"
#include "parse.hpp"
#include "common.hpp"

void sendUdp(netflowV5H *head, netflowV5R *record, arguments args)
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

    if (sendto(socket_fd, head, sizeof(*head), 0, (struct sockaddr*)&args.address, addrlen) == -1) {
        perror("sendto: ");
    };
}

int main(int argc, char **argv)
{
    arguments args;

    try
    {
        parse_arguments(argc, argv, args);
    }
    catch(const std::exception& e)
    {
        std::cerr << "ERROR: " << e.what() << '\n';
    }

    std::string line;
    // while (!(line = args.readline()).empty()) {
    //     std::cout << line;
    // }


    // const unsigned char *packet;
    // struct pcap_pkthdr header;
    // char error_buffer[PCAP_ERRBUF_SIZE];
    // int ip_header_length;
    // const unsigned char *ip_header;
    // struct ether_header *eth_header;
    // struct sockaddr_in server;

    // int counter = 0;

    // pcap_t *handle = pcap_open_offline("test.pcap", error_buffer);

    // while ((packet = pcap_next(handle, &header)) != NULL) {
    //     eth_header = (struct ether_header *) packet;
    //         if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
    //     dfprintf("[flow.cpp] Not an IPv4 packet. Skipping...\n")
    //     continue;
    // }
    //     ip_header = packet + 14;
    //     ip_header_length = ((*ip_header) & 0x0F);
    //     ip_header_length = ip_header_length * 4;
    //     unsigned char protocol = *(ip_header + 9);
    //     dfprintf("[flow.cpp] Protocol %d\n", protocol)

    //     counter++;
    // }

    // dfprintf("[flow.cpp] All packets processed %d\n", counter)

    netflowV5H head {};
    head.version = htons(5);
    head.count = htons(1);
    head.SysUpTime = htonl(5000);
    head.unix_secs = htonl(1664214475);

    netflowV5R record {};
    record.prot = 6;

    sendUdp(&head, &record, args);

    return 0;
}