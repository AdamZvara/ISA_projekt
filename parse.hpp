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

#define DEF_COLLECTOR   "127.0.0.1"
#define DEF_PORT        2055
#define DEF_ACTIVE      60
#define DEF_INACTIVE    10
#define DEF_COUNT       1024

/**
 * @brief Structure storing values from command line used
 *  throughout the program
 *
 * @note __line is internal variable to store input from file or standard input
 */
struct arguments
{
    std::istream* file      = &std::cin;        // default input file
    std::string collector   = DEF_COLLECTOR;    // collector hostname
    sockaddr_storage address;                   // collector IP address
    uint16_t port           = DEF_PORT;         // port number
    uint32_t active         = DEF_ACTIVE;       // active timer
    uint32_t inactive       = DEF_INACTIVE;     // inactive timer
    uint32_t cache_size     = DEF_COUNT;        // flow cache size
    std::string __line;

    /**
     * @brief Construct a new arguments object with default address (ipv4 localhost)
     */
    arguments()
    {
        sockaddr_in defaddr;
        defaddr.sin_family = AF_INET;
        inet_pton(AF_INET6, DEF_COLLECTOR, &(defaddr.sin_addr.s_addr));
        memcpy(&address, &defaddr, sizeof(address));
    }

    /**
     * @brief Return single line read from input file
     *
     * @return Line read from input file
     */
    std::string readline()
    {
        if (file->eof())
            __line.clear();
        else
            getline(*file, __line);
        return __line;
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