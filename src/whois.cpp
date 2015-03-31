#include "whois.h"

using namespace std;

// Forward Declarations
void writeFile(const char* ip, string response);

string getWhois(char* query)
{
	string response;
	string src = "./filters/whois/";
	src.append(query);
	ifstream whoisLog(src.c_str(), ios_base::in);

	if(whoisLog.fail())
	{
		queryWhois("whois.iana.org", query, &response);

		vector<string> lines;
		string_split(response, ' ', lines);
		for(size_t i = 0; i < lines.size(); ++i)
		{
			if(lines[i].find("whois.") != string::npos)
			{
				queryWhois(&(lines[i][lines[i].find("whois.")]), query, &response);
				break;
			}
		}
	} else if (whoisLog.is_open() == true)
	{
		string data;
		while(getline(whoisLog, data))
		{
			response.append(data);
		}
	}
	
	return response;
}

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

	if(send(s, query, strlen(query) , 0) < 0)
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
		}
	}

	close(s);
	
	return;
}

void writeFile(const char* ip, string response)
{
	string dest = "./filters/whois/";
	dest.append(ip);
	ofstream config(dest.c_str(), ios_base::out);
	config << response;
	config.close();
}

