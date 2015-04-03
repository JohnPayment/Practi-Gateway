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

struct smrt
{
	std::string subnet;
	std::string netname;
	std::string org;
	std::string lastupdate;

	std::string address;
	std::string city;
	std::string provcode;
	std::string country;
};

std::string getWhois(char* query);

void queryWhois(const char* server, const char* query, std::string* response);

void smartLog(char* ip, smrt* log);
std::string getPortUsage(unsigned int port);

#endif
