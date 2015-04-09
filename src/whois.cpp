#include "whois.h"

using namespace std;

// Forward Declarations
void writeFile(const char* ip, const string* response);

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	getWhois()
-- DATE:		2015-03-30
-- PARAMETERS:	char* query - The ip address to get Whois information
-- RETURN:		A string containing all of the whois information.
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		Takes an IP address in a c string and gets whois information for that address.
--				The function first checks for this info in a file at /filter/whois/ and only
--				If there is no local data does it perform a net search.
------------------------------------------------------------------------------------------------
*/
string getWhois(char* query)
{
	string response;
	string src(config::whoisDirectory());
	src.append(query);
	ifstream whoisLog(src.c_str(), ios_base::in);

	if(whoisLog.fail())
	{
		queryWhois("whois.iana.org", query, &response);

		stringstream repstream(response);
		string line;
		size_t pos = 0;
		while(getline(repstream, line))
		{
			if((pos = line.find("whois.")) != string::npos)
			{
				queryWhois(&(line[pos]), query, &response);
				break;
			}
		}

		writeFile(query, &response);
	} else if (whoisLog.is_open() == true)
	{
		string data;
		while(getline(whoisLog, data))
		{
			response.append(data);
			response.append("\n");
		}
	}

	whoisLog.close();
	return response;
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	queryWhois()
-- DATE:		2015-03-30
-- PARAMETERS:	const char* server - the first whois server to start whois lookup
--				const char* query - The ip address to get Whois information
--				string* response - A pointer to a string which will store looked up whois info.
-- RETURN:		void
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		Performs whois lookup over a network on the ip address in query.
------------------------------------------------------------------------------------------------
*/
void queryWhois(const char* server, const char* query, string* response)
{
	char buffer[1000];

	struct sockaddr_in dest;
	int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;

	struct hostent *he;

	if((he = gethostbyname(server)) == NULL) 
	{
		return;
	}

	memcpy(&dest.sin_addr, he->h_addr_list[0], he->h_length);
	dest.sin_port = htons(43);

	if(connect(s, (const struct sockaddr*)&dest , sizeof(dest)) < 0)
	{
		return;
	}

	string message(query);
	message.append("\r\n");
	if(send(s, message.c_str(), message.size() , 0) < 0)
	{
		close(s);
		return;
	}

	int size = 0;
	while((size = recv(s, buffer, sizeof(buffer), 0)))
	{
		if(size > 0)
		{
			response->append(buffer, size);
		} else
		{
			break;
		}
	}

	close(s);
	
	return;
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	smartLog()
-- DATE:		2015-04-01
-- PARAMETERS:	char* ip - The ip address for which smart log info is required
--				smrt* log - A pointer to the smrt structure to be populated
-- RETURN:		boid
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		Populates a smrt structure with data.
------------------------------------------------------------------------------------------------
*/
void smartLog(char* ip, smrt* log)
{
	string rawLog(getWhois(ip));
	stringstream logstream(rawLog);

	string data;
	while(getline(logstream, data))
	{
		size_t place = 0;
		if(data.find("No whois data") != string::npos)
		{
			break;
		} else if((place = data.find("CIDR:")) != string::npos)
		{
			place += strlen("CIDR:");
			for(; place < data.size(); ++place)
			{
				if(data[place] != ' ')
				{
					break;
				}
			}
			log->subnet.assign(data.substr(place));
		} else if((place = data.find("NetName:")) != string::npos)
		{
			place += strlen("NetName:");
			for(; place < data.size(); ++place)
			{
				if(data[place] != ' ')
				{
					break;
				}
			}
			log->netname.assign(data.substr(place));
		} else if((place = data.find("Organization:")) != string::npos)
		{
			place += strlen("Organization:");
			for(; place < data.size(); ++place)
			{
				if(data[place] != ' ')
				{
					break;
				}
			}
			log->org.assign(data.substr(place));
		} else if((place = data.find("Updated:")) != string::npos)
		{
			place += strlen("Updated:");
			for(; place < data.size(); ++place)
			{
				if(data[place] != ' ')
				{
					break;
				}
			}
			log->lastupdate.assign(data.substr(place));
		} else if((place = data.find("Address:")) != string::npos)
		{
			place += strlen("Address:");
			for(; place < data.size(); ++place)
			{
				if(data[place] != ' ')
				{
					break;
				}
			}
			log->address.assign(data.substr(place));
		} else if((place = data.find("City:")) != string::npos)
		{
			place += strlen("City:");
			for(; place < data.size(); ++place)
			{
				if(data[place] != ' ')
				{
					break;
				}
			}
			log->city.assign(data.substr(place));
		} else if((place = data.find("StateProv:")) != string::npos)
		{
			place += strlen("StateProv:");
			for(; place < data.size(); ++place)
			{
				if(data[place] != ' ')
				{
					break;
				}
			}
			log->provcode.assign(data.substr(place));
		} else if((place = data.find("Country:")) != string::npos)
		{
			place += strlen("Country:");
			for(; place < data.size(); ++place)
			{
				if(data[place] != ' ')
				{
					break;
				}
			}
			log->country.assign(data.substr(place));
		}
	}
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	getPortUsage()
-- DATE:		2015-03-30
-- PARAMETERS:	unsigned int port - The port number to look up
-- RETURN:		A string containing the port data, if any.
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		Looks up dara about the given port locally and returns the a string with any data
--				found.
------------------------------------------------------------------------------------------------
*/
string getPortUsage(unsigned int port)
{
	ifstream log(config::portFile().c_str());
	string data;
	while(getline(log, data))
	{
		if(port == atoi(data.c_str()))
		{
			return data.substr(7);
			break;
		}
	}
	data.assign("No Common Uses Documented.");
	return data;
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	writeFile()
-- DATE:		2015-03-30
-- PARAMETERS:	const char* ip - The ip address and file name for which whois info should be logged.
--				string response - The whois data to be logged
-- RETURN:		void
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		Writes whois information for a particular IP address to a file of the same name.
------------------------------------------------------------------------------------------------
*/
void writeFile(const char* ip, const string* response)
{
	string dest(config::whoisDirectory());
	dest.append(ip);
	ofstream config(dest.c_str(), ios_base::out);
	config << *response;
	config.close();
}

