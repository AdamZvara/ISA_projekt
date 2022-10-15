/**
 * @file flow.hpp
 * @author xzvara01 (xzvara01@stud.fit.vutbr.cz)
 * @brief Provide declarations for NetFlow (version 5) structures
 * @date 2022-10-06
 *
 */

#ifndef _FLOW_HPP
#define _FLOW_HPP 1

#include <vector>
#include <cstdint>          // uintX types

#include "src/parse.hpp"


struct __attribute__((packed)) netflowV5H
{
    uint16_t version;
    uint16_t count;
    uint32_t SysUpTime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint8_t  engine_type;
    uint8_t  engine_id;
    uint16_t sampling_interval;

};

struct __attribute__((packed)) netflowV5R
{
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t nexthop;
    uint16_t input;
    uint16_t output;
    uint32_t dPkts;
    uint32_t dOctets;
    uint32_t First;
    uint32_t Last;
    uint16_t srcport;
    uint16_t dstport;
    uint8_t  pad1;
    uint8_t  tcp_flags;
    uint8_t  prot;
    uint8_t  tos;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t  src_mask;
    uint8_t  dst_mask;
    uint16_t pad2;
};

/**
 * @brief Send data with given size over UDP to address
 *
 * @param[in] data    data to be sent
 * @param[in] size    size of data
 * @param[in] address address to send to
 * @param[in] port    port to send to
 *
 * @throw runtime_error socket() or sendto() failed
 */
void sendUdp(const char *data, const size_t size, sockaddr_storage& address, const uint16_t port);

char *prepare_structs(std::vector<netflowV5R> flows, size_t& buff_size);


#endif