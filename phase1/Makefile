CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread

TARGETS = server client

all: $(TARGETS)

server: server.cpp
	$(CXX) $(CXXFLAGS) -o server server.cpp

client: client.cpp
	$(CXX) $(CXXFLAGS) -o client client.cpp

clean:
	rm -f $(TARGETS)

.PHONY: all clean
