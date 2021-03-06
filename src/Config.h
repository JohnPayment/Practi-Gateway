#ifndef CONFIG_H
#define CONFIG_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

#include <vector>
#include <algorithm>
using namespace std;

namespace config
{
	// User Variables
	//const string& protocols();
	//const string& firewallFilter();
	const string& loggingFilter();
	const string& repoFilter();
	//const string& broadcastInterface();
	//const string& externalInterface();

	// Routing Variables
	//const string& ssid();
	//bool nmode();
	//int wmode();
	//const string& password();

	// Firewall Variables
	//bool firewall();

	// Logging Variables
	bool logging();
	bool smartLookup();

	const string& logDirectory();
	const string& whoisDirectory();
	const string& portFile();

	// Payload Replacement Variables
	bool payloadReplacement();
}

void getConfig(const char* file);
void makeConfig();

vector<string> &string_split(const string &s, char delim, vector<string> &dest);

#endif
