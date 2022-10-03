/**
 * @file parse.hpp
 * @author xzvara01, xzvara01@stud.fit.vutbr.cz
 * @brief Header file for parsing command line arguments
 * @date September 2022
 */

#ifndef PARSE_HPP
#define PARSE_HPP 1

#include <fstream>
#include <string>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>          // pton
#include <netinet/in.h>         // sockaddr_in, in_addr
#include <netdb.h>              // getaddrinfo

#define DEF_COLLECTOR   "127.0.0.1"
#define DEF_PORT        2055
#define DEF_ACTIVE      60
#define DEF_INACTIVE    10
#define DEF_COUNT       1024

/**
 * @brief Structure storing values from command line used
 *  throughout the program
 */
struct arguments
{
    std::istream* file      = &std::cin;        // default input file
    bool _file_allocd       = false;            // indicator that file has been opened and needs to be freed
    std::string collector   = DEF_COLLECTOR;    // collector hostname
    sockaddr_storage address;                   // collector IP address
    uint16_t port           = DEF_PORT;         // port number
    uint32_t active         = DEF_ACTIVE;       // active timer
    uint32_t inactive       = DEF_INACTIVE;     // inactive timer
    uint32_t cache_size     = DEF_COUNT;        // flow cache size

    /**
     * @brief Construct a new arguments object with default address (ipv4 localhost)
     */
    arguments()
    {
        addrinfo hints = {}, *address_list;
        hints.ai_family = AF_INET;
        hints.ai_flags = AI_NUMERICHOST;

        getaddrinfo(DEF_COLLECTOR, NULL, &hints, &address_list);
        memcpy(&address, address_list->ai_addr, address_list->ai_addrlen);
        freeaddrinfo(address_list);
    }

    ~arguments()
    {
        if (_file_allocd) {
            delete file;
        }
    }

};

/**
 * @brief Return converted string argument as number

 * @param[in] str_number Argument to convert
 * @return Integer representation of argument
 *
 * @throw invalid_argument Argument could not be converted
 */
int arg_to_number(const char *str_number);

/**
 * @brief Parse optarg hostname[]:port] into separate variables
 *
 * @param[in]  original         Optarg hostname[:port] combination
 * @param[out] parsed_hostname  Parsed hostname
 * @param[out] parsed_port      Parsed port number
 */
void parse_hostname(char *original, std::string& parsed_hostname, uint16_t& parsed_port);

/**
 * @brief Parse arguments from command line into arguments structure
 *
 * @param[in]  argc Number of arguments
 * @param[in]  argv Vector of arguments
 * @param[out] args Command line options values
 *
 * @throw invalid_argument When one of arguments could not be converted to a number
 *  (see function arg_to_number)
 */
void parse_arguments(int argc, char **argv, arguments& args);

#endif