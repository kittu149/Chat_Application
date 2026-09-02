CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread -I/usr/include/openssl -I/opt/homebrew/opt/openssl/include
LDFLAGS = -L/usr/lib -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto -pthread

TARGETS = server client

all: $(TARGETS)

server: server.cpp crypto.cpp crypto.h
	$(CXX) $(CXXFLAGS) -o server server.cpp crypto.cpp $(LDFLAGS)

client: client.cpp crypto.cpp crypto.h
	$(CXX) $(CXXFLAGS) -o client client.cpp crypto.cpp $(LDFLAGS)

clean:
	rm -f $(TARGETS) *.crt *.key *.csr *.srl

.PHONY: all clean
