/**
 * @file store.hpp
 * @author xzvara01 (xzvara01@stud.fit.vutbr.cz)
 * @brief Header file for storing flows created by the program
 * @date 2022-10-06
 *
 */

#ifndef _STORE_HPP
#define _STORE_HPP 1

#include <cstdint>          // uintX types
#include <map>
#include <tuple>

#include "../flow.hpp"      // netflow structures
#include "capture.hpp"      // capture structure

extern uint64_t SysUpTime;
extern uint64_t LastTime;

// Key for saving netflow records in flow_cache consisting of srcip, dstip, srcport, dstport and protocol
typedef std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> netkey_t;

// Flow_cache
typedef std::map<netkey_t, netflowV5R> flowc_t;

void make_header(netflowV5H& header, int count);

void flow_insert(Capture& cap, flowc_t& flow_cache);

void update_flow(Capture &cap, netflowV5R& flow);

void create_flow(Capture &cap, netflowV5R& flow, uint16_t Sportn, uint16_t Dportn);

void get_ports(Capture& cap, uint16_t& Sportn, uint16_t& Dportn);

bool time_second_passed(time_t sec, suseconds_t usec);

int get_packet_timestamp(Capture &cap);

#endif