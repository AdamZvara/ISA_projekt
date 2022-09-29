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

#define DEF_PORT        2055
#define DEF_ACTIVE      60
#define DEF_INACTIVE    10
#define DEF_COUNT       1024

struct arguments 
{
    std::ifstream file;
    std::string collector = "127.0.0.1";
    int port = DEF_PORT;
    int active = DEF_ACTIVE;
    int inactive = DEF_INACTIVE;
    int count = DEF_COUNT;
};

void parse_arguments(int argc, char **argv, arguments& args);

#endif