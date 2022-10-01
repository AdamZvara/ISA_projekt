/**
 * @file common.hpp
 * @author xzvara01, xzvara01@stud.fit.vutbr.cz
 * @brief Declaration of common functions/macros (eg. debug print)
 * @date September 2022
 */

#ifndef COMMON_HPP
#define COMMON_HPP 1

#include <iostream>
#include <string>
#include <unistd.h>             // close
#include <netinet/in.h>         // sockaddr_in, in_addr

/* Define return values */
#define OK 0

/* Define debug macros */
#define DEBUG_MAIN 0
#if DEBUG_MAIN == 1
    #define dfprintf(...) {fprintf(stderr, __VA_ARGS__);}
#else
    #define dfprintf(...) {}
#endif

#define DEBUG_PARSE 1
#if DEBUG_PARSE == 1
    #define dpprintf(...) {fprintf(stderr, __VA_ARGS__);}
#else
    #define dpprintf(...) {}
#endif

/* Declaration of common functions */

/**
 * @brief Convert hostname into structure sockaddr stored in structure arguments
 * 
 * @param[in]  hostname     String hostname
 * @param[out] out_address  sockaddr structure to store converted IP address
 */
void convert_hostname(std::string hostname, sockaddr& out_address);

#endif