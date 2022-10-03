/**
 * @file parse.cpp
 * @author xzvara01, xzvara01@stud.fit.vutbr.cz
 * @brief Main file for parsing command line arguments
 * @date September 2022
 */

#include <unistd.h>
#include <cstring>  //strlen

#include "parse.hpp"
#include "common.hpp"

#define OPTIONS "hf:c:a:i:m:P"

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

void debug_print_options(arguments& args)
{
    dpprintf("[parse.cpp] active\t%d\n", args.active);
    dpprintf("[parse.cpp] inactive\t%d\n", args.inactive);
    dpprintf("[parse.cpp] port\t%d\n", args.port);
    dpprintf("[parse.cpp] cache size\t%d\n", args.cache_size);
    dpprintf("[parse.cpp] collector\t%s\n", args.collector.c_str());
}

int arg_to_number(const char *str_number)
{
    int converted_num;
    char* end; // check if numerical values are converted correctly

    converted_num = strtol(str_number, &end, 10);
    if (strlen(end) != 0) {
        throw std::invalid_argument("Argument followed by an invalid number");
    } else if (converted_num < 0) {
        throw std::invalid_argument("Argument must be followed by a positive number");
    }
    return converted_num;
}

void parse_hostname(char *original, std::string& parsed_hostname, uint16_t& parsed_port)
{
    // try to find port number and parse it
    size_t pos = 0;
    std::string hostname = original;
    std::string delim = ":";
    std::string str_port;

    if (is_valid_ipv6(original)) {
        parsed_hostname = hostname;
        return;
    }

    if ((pos = hostname.find_last_of(delim)) != std::string::npos) {
        str_port = hostname.substr(pos+1); // port number starts at pos+1 because of the colon
        hostname.erase(pos);
        parsed_port = arg_to_number(str_port.c_str()); // convert port string to integer
    }

    parsed_hostname = hostname;
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

        case 'a':
            args.active = arg_to_number(optarg);
            break;

        case 'i':
            args.inactive = arg_to_number(optarg);
            break;

        case 'm':
            args.cache_size = arg_to_number(optarg);
            break;

        case 'f':
            args.file = new std::ifstream(optarg);
            break;

        case 'c':
            parse_hostname(optarg, args.collector, args.port);
            convert_hostname(args.collector, &(args.address));
            break;

        default:
            break;
        }

    }
    debug_print_options(args);
}