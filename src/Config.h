#ifndef CONFIG_H
#define CONFIG_H
#include <stdio.h>
#include <string.h>

#include <iostream>
#include <fstream>
#include <sstream>
using namespace std;

namespace config
{
	// User Variables
	const string& protocols();
	const string& firewallFilter();
	const string& loggingFilter();
	const string& repoFilter();
	const string& broadcastInterface();

	// Routing Variables
	const string& ssid();
	bool nmode();
	int wmode();
	const string& password();

	// Firewall Variables
	bool firewall();

	// Logging Variables
	bool logging();
	bool smartLookup();

	// Payload Replacement Variables
	bool payloadReplacement();
}

void getConfig(const char* file);
void makeConfig();
#endif

