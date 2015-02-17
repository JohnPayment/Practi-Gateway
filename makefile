CC = g++
CFLAGS  = -g -Wall

# typing 'make' will invoke the first target entry in the file 
# (in this case the default target entry)
# you can name this target entry anything, but "default" or "all"
# are the most commonly used names by convention
default: gateway

gateway: gateway.o routing.o config.o
	$(CC) $(CFLAGS) Gateway.o Routing.o Config.o -o practiGateway.exe

gateway.o: Gateway.cpp Config.h 
	$(CC) $(CFLAGS) -c Gateway.cpp

routing.o: Routing.cpp Routing.h Config.h
	$(CC) $(CFLAGS) -c Routing.cpp	

config.o: Config.cpp Config.h 
	$(CC) $(CFLAGS) -c Config.cpp

clean:
	$(RM) gateway *.o *~
