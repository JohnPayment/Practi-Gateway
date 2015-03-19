#include "Config.h"
using namespace config;

// User Variables
string _protocols;
string _firewallFilter;
string _loggingFilter;
string _repoFilter;
string _broadcastInterface;
string _externalInterface;

// Routing Variables
string _ssid;
bool _nmode = true; // Infrastructure mode = true, Adhoc = false
int _wmode = 0; // 0 = Disabled, +1 = Enabled, -1 = Automatic
string _password;

// Firewall Variables
bool _firewall = false;

// Logging Variables
bool _logging = false;
bool _smartLookup = false;

// Payload Replacement Variables
bool _payloadReplacement = false;

// User Variables
const string& config::protocols() {return _protocols;}
const string& config::firewallFilter() {return _firewallFilter;}
const string& config::loggingFilter() {return _loggingFilter;}
const string& config::repoFilter() {return _repoFilter;}
const string& config::broadcastInterface() {return _broadcastInterface;}
const string& config::externalInterface() {return _externalInterface;}

// Routing Variables
const string& config::ssid() {return _ssid;}
bool config::nmode() {return _nmode;}
int config::wmode() {return _wmode;}
const string& config::password() {return _password;}

// Firewall Variables
bool config::firewall() {return _firewall;}

// Logging Variables
bool config::logging() {return _logging;}
bool config::smartLookup() {return _smartLookup;}

// Payload Replacement Variables
bool config::payloadReplacement() {return _payloadReplacement;}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	getConfig()
-- REVISION:	2015-03-11
-- PARAMETERS:	const char* file - The name of the file from which config variables should be loaded.
-- RETURN:		void
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		This function loads config variables based upon the contents of the specified
--				file.
------------------------------------------------------------------------------------------------
*/
void getConfig(const char* file)
{
	ifstream config(file);
	if(config.fail())
	{
		cout << "invalid config file" << endl;
		return;
	}
	if(config.is_open() == true)
	{
		string data;
		while(getline(config, data))
		{
			if(config.eof())
			{
				break;
			}
			if(data.find("protocols:") != string::npos)
			{
				_protocols.clear();
				_protocols.append(data.substr(10));
			} else if(data.find("firewall-filter:") != string::npos)
			{
				_firewallFilter.clear();
				_firewallFilter.append(data.substr(16));
			} else if(data.find("logging-filter:") != string::npos)
			{
				_loggingFilter.clear();
				_loggingFilter.append(data.substr(15));			
			} else if(data.find("repo-filter:") != string::npos)
			{
				_repoFilter.clear();
				_repoFilter.append(data.substr(12));
			} else if(data.find("broadcastinterface:") != string::npos)
			{
				_broadcastInterface.clear();
				_broadcastInterface.append(data.substr(19));
			} else if(data.find("externalinterface:") != string::npos)
			{
				_externalInterface.clear();
				_externalInterface.append(data.substr(18));
			} else if(data.find("ssid:") != string::npos)
			{
				_ssid.clear();
				_ssid.append(data.substr(5));
			} else if(data.find("nmode:") != string::npos)
			{
				if(data.find("infrastructure") != string::npos)
				{
					_nmode = true;
				} else
				{
					_nmode = false;
				}
			} else if(data.find("wpa:") != string::npos)
			{
				if(data.find("on") != string::npos)
				{
					_wmode = 1;
				} else if(data.find("auto") != string::npos)
				{
					_wmode = -1;
				} else
				{
					_wmode = 0;
				}
			} else if(data.find("password:") != string::npos)
			{
				_password.clear();
				_password.append(data.substr(9));
			} else if(data.find("firewall:") != string::npos)
			{
				if(data.find("on") != string::npos)
				{
					_firewall = true;
				} else
				{
					_firewall = false;
				}
			} else if(data.find("logging:") != string::npos)
			{
				if(data.find("on") != string::npos)
				{
					_logging = true;
				} else
				{
					_logging = false;
				}
			} else if(data.find("smartlookup:") != string::npos)
			{
				if(data.find("on") != string::npos)
				{
					_smartLookup = true;
				} else
				{
					_smartLookup = false;
				}
			} else if(data.find("payloadreplacement:") != string::npos)
			{
				if(data.find("on") != string::npos)
				{
					_payloadReplacement = true;
				} else
				{
					_payloadReplacement = false;
				}
			}
		}
		config.close();
	}
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	makeConfig()
-- REVISION:	2015-03-11
-- PARAMETERS:	N/A
-- RETURN:		void
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		Writes a new config file with default parameters.
------------------------------------------------------------------------------------------------
*/
void makeConfig()
{
	ofstream config("config", ios_base::out);
	config << "===============" << endl;
	config << " User Settings " << endl;
	config << "===============" << endl;
	config << "protocols:./protocols" << endl;
	config << "firewall-filter:./filters/firewall" << endl;
	config << "logging-filter:./filters/logger" << endl;
	config << "repo-filter:./filters/replacer" << endl << endl;

	config << "==================" << endl;
	config << " Routing Settings " << endl;
	config << "==================" << endl;
	config << "broadcastInterface:wlan0" << endl;
	config << "externalInterface:em1" << endl;
	config << "ssid:testgateway" << endl;
	config << "nmode:infrastructure" << endl;
	config << "wpa:off" << endl;
	config << "password:password" << endl << endl;

	config << "inter-ip:10.240.47.0" << endl;
	config << "exter-ip:192.168.2.10" << endl << endl;

	config << "===================" << endl;
	config << " Firewall Settings " << endl;
	config << "===================" << endl;
	config << "firewall:off" << endl << endl;

	config << "==================" << endl;
	config << " Logging Settings " << endl;
	config << "==================" << endl;
	config << "logging:off" << endl;
	config << "smartlookup:off" << endl << endl;

	config << "=====================" << endl;
	config << " Payload Replacement " << endl;
	config << "=====================" << endl;
	config << "payloadreplacement:off" << endl << endl;

	config.close();
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	string_split()
-- DATE:		2015-03-13
-- PARAMETERS:	const string &s - The string to be split.
--				char delim - The character on which to split the string.
--				vector<string> &dest - The vector in which the resulting string elements should be stored.
-- RETURN:		vector<string>& - Returns a references to the vector which is storing the split string elements
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		This function splits a string on the delimited character and stores the
--				resulting elements in dest.
------------------------------------------------------------------------------------------------
*/
vector<string> &string_split(const string &s, char delim, vector<string> &dest)
{
	stringstream ss(s);
	string item;
	while(std::getline(ss, item, delim)) 
	{
		item.erase(remove_if(item.begin(), item.end(), ::isspace ), item.end() );
		transform(item.begin(), item.end(), item.begin(), ::tolower);
		dest.push_back(item);
	}
	return dest;
}

