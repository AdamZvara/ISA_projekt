/**
 * @file capture.hpp
 * @author xzvara01 (xzvara01@stud.fit.vutbr.cz)
 * @brief Header file for capturing incoming traffic
 * @date 2022-10-06
 *
 */

#ifndef _CAPTURE_HPP
#define _CAPTURE_HPP 1

#include <pcap.h>
#include <netinet/ip.h>         // struct iphdr
#include <netinet/if_ether.h>   // struct ether_header

#define ERR_INCOMPLETE -4
#define ERR_NONETH     -5

class Capture
{
private:
    pcap_t *handle;                     // handler to opened pcap file
    struct bpf_program fp;              // filter program
    char errbuf[PCAP_ERRBUF_SIZE];      // error buffer

public:
    const unsigned char *packet;        // captured packet
    pcap_pkthdr *header;                // captured packet header
    iphdr *ip_header;                   // ip header
    ether_header *eth_header;           // ethernet header
    void *transport_header;             // trasnport header (later casted to the correct type)
    /**
     * @brief Destroy the Capture object and free all allocated memory
     *
     */
    ~Capture();

    /**
     * @brief Initialize pcap handler to open given file
     *
     * @param[in] filename Name of the file
     *
     * @throw runtime_error Pcap handler could not be initialized
     */
    void open(FILE* file);

    /**
     * @brief Apply filter_expr to pcap handler
     *
     * @param[in] filter_expr Expression to be applied
     */
    void apply_filter(const char* filter_expr);

    /**
     * @brief Get next packet from savefile and parse it to public structures (header, iphdr, ethhdr ...)
     *
     * @return int Return value from function pcap_next_ex
     *
     * @throw runtime_error If any header was not complete or link layer header was not ETHERNET
     */
    int next_packet();
};

#endif