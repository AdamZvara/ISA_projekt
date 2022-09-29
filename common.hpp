/**
 * @file common.hpp
 * @author xzvara01, xzvara01@stud.fit.vutbr.cz
 * @brief Declaration of common functions/macros (eg. debug print)
 * @date September 2022
 */

#ifndef COMMON_HPP
#define COMMON_HPP 1

#define DEBUG 1
#if DEBUG == 1
    #define dprintf(...) {printf(__VA_ARGS__);}
#else
    #define dprintf(...) {}
#endif

#endif