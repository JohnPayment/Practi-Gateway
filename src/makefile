CC = g++
CFLAGS  = -g -Wall -lpthread -lnetfilter_queue

# typing 'make' will invoke the first target entry in the file 
# (in this case the default target entry)
# you can name this target entry anything, but "default" or "all"
# are the most commonly used names by convention
default: gateway

gateway: gateway.o routing.o payload.o logging.o whois.o config.o
	$(CC) $(CFLAGS) Gateway.o Routing.o Payload.o Logging.o whois.o Config.o -o ../practiGateway.exe

gateway.o: Gateway.cpp Config.h 
	$(CC) $(CFLAGS) -c Gateway.cpp

routing.o: Routing.cpp Routing.h Payload.h Logging.h Config.h
	$(CC) $(CFLAGS) -c Routing.cpp

payload.o: Payload.cpp Payload.h Logging.h Config.h
	$(CC) $(CFLAGS) -c Payload.cpp

logging.o: Logging.cpp Logging.h whois.h Config.h
	$(CC) $(CFLAGS) -c Logging.cpp

whois.o: whois.cpp whois.h Config.h
	$(CC) $(CFLAGS) -c whois.cpp

config.o: Config.cpp Config.h
	$(CC) $(CFLAGS) -c Config.cpp

clean:
	$(RM) gateway *.o *~
