/**
 * @file debug.hpp
 * @author xzvara01 (xzvara01@stud.fit.vutbr.cz)
 * @brief Debug output file
 * @date 2022-10-06
 *
 */

#ifndef _DEBUG_HPP
#define _DEBUG_HPP 1

/* Define return values */
#define DEBUG_STRING "srcIP %u, dstIP %u, srcPort %u, dstPort %u, protocol %u, first %u, last %u, octets %u, packets %u\n"

/* Define debug macros */
#define DEBUG_MAIN 0
#if DEBUG_MAIN == 1
    #define dfprintf(...) {fprintf(stderr, __VA_ARGS__);}
    #define dsfprintf() {\
        fprintf(stderr, DEBUG_STRING, record->second.srcaddr, record->second.dstaddr, record->second.srcport,\
        record->second.dstport, record->second.prot, record->second.First, record->second.Last, record->second.dOctets, record->second.dPkts);}
#else
    #define dfprintf(...) {}
    #define dsfprintf() {}
#endif

#define DEBUG_PARSE 0
#if DEBUG_PARSE == 1
    #define dpprintf(...) {fprintf(stderr, __VA_ARGS__);}
#else
    #define dpprintf(...) {}
#endif

#define DEBUG_FLOWCACHE 1
#if DEBUG_FLOWCACHE == 1
    #define dfcprintf(...) {\
        for (auto item = flow_cache.cbegin(); item != flow_cache.cend(); ++item) {\
            fprintf(stderr, DEBUG_STRING,\
            item->second.srcaddr, item->second.dstaddr, item->second.srcport, item->second.dstport, item->second.prot,\
            item->second.First, item->second.Last, item->second.dOctets, item->second.dPkts);}}
#else
    #define dfcprintf(...) {}
#endif

#endif