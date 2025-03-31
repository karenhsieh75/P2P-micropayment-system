all: server client

server: server_stage3.cpp
	g++ server_stage3.cpp -pthread -lssl -lcrypto -o server

client: client_stage3.cpp
	g++ client_stage3.cpp -pthread -lssl -lcrypto -o client

clean:
	rm -f server client
