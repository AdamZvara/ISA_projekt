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

#define ETH_HLEN 14
#define EXPORT_TIMER 1000
#define FCACHE_FULL -1

extern uint64_t SysUpTime;
extern timeval LastChecked;

// Key for saving netflow records in flow_cache consisting of srcip, dstip, srcport, dstport and protocol
typedef std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> netkey_t;

// Flow_cache
typedef std::map<netkey_t, netflowV5R> flowc_t;

/**
 * @brief Calculate time, when packet has been capture (relative to SysUpTime)
 *
 * @param[in] hdr pcap_pkthdr of captured packet
 * @return Calculated time
 */
int get_packet_timestamp(const pcap_pkthdr *hdr);

/**
 * @brief Check if certain amount of time passed since the last time flows from cache were exported
 * @details Since looking through flow cache each time new packet is recieved can be time consuming,
 *  this function checks, if time EXPORT_TIMER has passed since the last export of flows from cache,
 *  therefore limiting number of times when whole flow cache needs to be checked. Function works with
 *  global variable LastChecked.
 *
 * @param[in] sec  Packet timestamp in seconds
 * @param[in] usec Residual microseconds
 * @return true EXPORT_TIMER has been reached since last export of flows
 * @return false EXPORT_TIMER has not been reached
 */
bool time_second_passed(const time_t sec, const suseconds_t usec);

void fcache_find(const Capture& cap, flowc_t& flow_cache, netflowV5R *record);

bool tcp_rstfin(const Capture& cap);

/**
 * @brief Fill netflow v5 header with appropriate values
 *
 * @param[in] header netflow v5 header
 * @param[in] count amount of netflow records to be exported with this header
 */
void fill_header(netflowV5H& header, const int count);

/**
 * @brief Retrieve port numbers from captured packet
 *
 * @param[in]  cap    captured packet
 * @param[out] Sportn source port number
 * @param[out] Dportn destination port number
 */
void get_ports(const Capture& cap, uint16_t& Sportn, uint16_t& Dportn);

/**
 * @brief Update flow which is already stored in flow cache
 *
 * @param[in]  cap  captured packet
 * @param[out] flow flow to be updated
 */
void update_flow(const Capture &cap, netflowV5R& flow);

/**
 * @brief Create new flow to be inserted to flow cache
 *
 * @param[in]  cap    captured packet
 * @param[out] flow   reference to allocated flow
 * @param[in]  Sportn source port number
 * @param[in]  Dportn destination port number
 */
void create_flow(const Capture &cap, netflowV5R& flow, const uint16_t Sportn, const uint16_t Dportn);

/**
 * @brief Insert (or update) captured packet into flow cache
 *
 * @param[in]  cap        captured packet
 * @param[out] flow_cache flow cache
 * @param[in]  flowsize   maximum amount of flow cache items
 */
int flow_insert(const Capture& cap, flowc_t& flow_cache, uint64_t flowsize);

#endif