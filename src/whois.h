#ifndef WHOIS_H
#define WHOIS_H
#include "Config.h"
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>

#include<sys/socket.h>

#include<netdb.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#include <iostream>
#include <fstream>
#include <istream>

#include <vector>
#include <algorithm>

std::string getWhois(char* query);

void queryWhois(const char* server, const char* query, std::string* response);

#endif
