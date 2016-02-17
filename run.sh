rm -f server
rm -f client
gcc 201325118_assign_1_server.c -w -std=c99 -lm -lssl -lcrypto -o server
gcc 201325118_assign_1_client.c -w -lssl -lcrypto -lm -std=c99 -o client
