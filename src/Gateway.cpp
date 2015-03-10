#include "Config.h"
#include "Routing.h"
#include <unistd.h>

int main(int argc, const char* argv[])
{
	pthread_t incomingThread;
	int errno;

	if(getuid() != 0)
	{
		cout << "Permission denied: root privileges are required." << endl;
		return 1;
	}
	if(argc > 1)
	{
		getConfig(argv[1]);
	} else
	{
		char answer;
		cout << "No config file selected. Would you like to make one?" << endl;
		cout << "y/n: ";
		cin >> answer;
		if(answer == 'Y' || answer == 'y')
		{
			makeConfig();
			getConfig("config");
		} else if(answer != 'N' && answer != 'n')
		{
			cout << "Invalid input. Program terminated." << endl;
		}
		return 1;
	}

	rSetup();
	if((errno=pthread_create(&incomingThread, NULL, &incomingMasq, NULL)) != 0)
	{
		// Put logging here
		//printf("Thread creation failed: %d\n", rc1);
	}

	pthread_join(incomingThread, NULL);
	return 0;
}

