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
#include <iostream>

#include "flow.hpp"
#include "parse.hpp"
#include "common.hpp"

void sendUdp(netflowV5H *head, netflowV5R *record)
{
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd == -1) {
        return;
    }

    // set destination port and address for connection
    struct sockaddr_in dst_address;
    dst_address.sin_family = AF_INET;
    dst_address.sin_port = htons(9995);
    inet_pton(AF_INET, "127.0.0.1", &(dst_address.sin_addr.s_addr));  // convert string IP address

    /* Connect to given interface on given port and send packet*/
    if (connect(socket_fd, (struct sockaddr*)&dst_address, sizeof(dst_address)) == -1) {
        return;
    }

    sendto(socket_fd, head, sizeof(*head), 0, (struct sockaddr*)&dst_address, sizeof(dst_address));
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
    

    const unsigned char *packet;
    struct pcap_pkthdr header;
    char error_buffer[PCAP_ERRBUF_SIZE];
    int ip_header_length;
    const unsigned char *ip_header;
    struct ether_header *eth_header;
    struct sockaddr_in server;

    int counter = 0;

    pcap_t *handle = pcap_open_offline("test.pcap", error_buffer);

    while ((packet = pcap_next(handle, &header)) != NULL) {
        eth_header = (struct ether_header *) packet;
            if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        dprintf("flow.cpp: Not an IPv4 packet. Skipping...\n")
        continue;
    }
        ip_header = packet + 14;
        ip_header_length = ((*ip_header) & 0x0F);
        ip_header_length = ip_header_length * 4;
        unsigned char protocol = *(ip_header + 9);
        dprintf("flow.cpp: protocol %d\n", protocol)

        counter++;
    }

    dprintf("flow.cpp: all packets processed %d\n", counter)

    // netflowV5H head {};
    // head.version = htons(5);
    // head.count = htons(1);
    // head.SysUpTime = htonl(5000);
    // head.unix_secs = htonl(1664214475);

    // netflowV5R record {};
    // record.prot = 6;

    // sendUdp(&head, &record);

    return 0;
}