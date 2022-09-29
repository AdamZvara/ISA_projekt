/**
 * @file parse.cpp
 * @author xzvara01, xzvara01@stud.fit.vutbr.cz
 * @brief Main file for parsing command line arguments
 * @date September 2022
 */

#include <unistd.h>
#include <iostream>
#include <cstring>
#include <exception>

#include "parse.hpp"

#define OPTIONS "hf:c:a:i:m:"

void print_help()
{
    std::cerr << "Usage: ./flow [OPTIONS ...]\n" 
            << "Generate netflow records from pcap file which are sent to collector over UDP\n\n"
            << "OPTIONS\n" 
                << "  -f=FILENAME\t\tInput pcap file (default STDIN)\n"
                << "  -c=IP/HOSTNAME[:PORT]\tIP address or HOSTNAME of collector with optional UDP port (default 127.0.0.1:2055)\n"
                << "  -a=SECONDS\t\tInterval in seconds, after which active records are exported to collector (default 60 seconds)\n"
                << "  -i=SECONDS\t\tInterval in seconds, after which inactive records are exported to collector (default 10 seconds)\n"
                << "  -m=COUNT\t\tSize of flow cache (default 1024)\n";
}

int convert_number(char *str_number)
{
    int converted_num; 
    char* end; // check if numerical values are converted correctly

    converted_num = strtol(str_number, &end, 10);
    if (strlen(end) != 0) {
        throw std::invalid_argument("Argument followed by an invalid number");
    } else if (converted_num < 0) {
        throw std::invalid_argument("Argument must be followed by a non negative number");
    } 
    return converted_num;
}

void parse_arguments(int argc, char **argv, arguments& args)
{
    int c;

    while ((c = getopt(argc, argv, OPTIONS)) != -1) {
        switch (c)
        {
        case 'h': 
            print_help();
            break;

        case 'f':
            std::cout << "File was given" << '\n';
            break;
        
        case 'a':
            args.active = convert_number(optarg);
            break;

        case 'i':
            break;

        default:
            break;
        }
    }
}