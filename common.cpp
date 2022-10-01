/**
 * @file common.cpp
 * @author xzvara01, xzvara01@stud.fit.vutbr.cz
 * @brief Definitions of common functions
 * @date September 2022
 */

#include <netdb.h>              // getaddrinfo
#include "common.hpp"

void convert_hostname(std::string hostname, sockaddr& out_address)
{
    int error, sockfd;
    addrinfo hints = {}, *address_list;
    bool found = false;

    hints.ai_family = AF_UNSPEC; // get IPv4 and IPv6 addresses
    hints.ai_socktype = SOCK_DGRAM; // prefered UDP socket type
    hints.ai_protocol = IPPROTO_UDP; // prefered UDP protocol

    // getaddrinfo returns linked list with available IP addresses
    if ((error = getaddrinfo(hostname.c_str(), NULL, &hints, &address_list)) != 0) {
        std::string msg = "getaddrinfo failed: ";
        msg.append(gai_strerror(error));
        throw std::runtime_error(msg);
    }

    // iterate through linked list of addresses and try to connect to one
    for (addrinfo *address = address_list; address != NULL; address = address->ai_next) {
        // create new socket to connect to address
        if ((sockfd = socket(address->ai_family, address->ai_socktype, address->ai_protocol)) == -1) {
            // socket could not be created, continue to another address
            continue;
        }

        // try to connect to address
        if (connect(sockfd, address->ai_addr, address->ai_addrlen) == 0) {
            #if DEBUG_PARSE == 1 // debugging print
                char host[NI_MAXHOST];
                getnameinfo(address->ai_addr, address->ai_addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
                printf("[common.cpp] collIP\t%s\n", host);
            #endif

            // valid address was found
            out_address = *(address->ai_addr);
            found = true;
            close(sockfd);
            break;
        }

        close(sockfd);
    }

    freeaddrinfo(address_list);

    // no valid address was found
    if (!found) {
        throw std::runtime_error("no collector IP address could be resolved");
    }

}