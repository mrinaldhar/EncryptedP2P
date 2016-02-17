#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <ctype.h>
#include "RSA.c"

int listenSocket = 0;
int connectionSocket = 0;
char buffer[1024];
struct sockaddr_in s_serv_addr;
int portno = 5005;
char IP[25];
char perm;
key_pair public, private;

int initDownload(char *);
char* sendMsg(char *, int);
char *decode_string(char *);


void get_hash(char * data, char * buf) {
	int i;
	unsigned char hash[SHA_DIGEST_LENGTH];
    memset(hash, 0x0, SHA_DIGEST_LENGTH);
    memset(buf, 0x0, SHA_DIGEST_LENGTH);

	SHA1((unsigned char *)data, strlen(data), hash);
	for (i=0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf((char*)&(buf[i*2]), "%02x", hash[i]);
    }
 
    // printf("SHA1 of %s is %s\n", data, buf);
}

void cpy(char * a, char * b) {
	int i, j;
	i=j=0;
	while (b[i]!='\0') {
		a[i] = b[i];
		i++;
	}
	a[i] = '\0';
}


int main(int argc, char **argv) {
	listenSocket = socket(AF_INET,SOCK_STREAM,0);

	KeyGen(&public, &private); 
	strcpy(IP, argv[1]);
	
	char * buf; 
	buf = strdup(argv[2]);

	char filename[50];
	char chat_msg[50];

	
	char * returncode;
	
	bzero(filename, 50);
	filename[0] = 'k';		// Send Public Key
	filename[1] = '\0';

	sprintf(filename+1, "%lld:", public.public_key.e);
	sprintf(filename+strlen(filename), "%lld\0", public.public_key.n);
	printf("Key generated: %s\n", filename);
	sendMsg(filename, 0); 
	bzero(filename, 50);
	cpy(filename+1, buf);
	filename[0] = 'd';		// Get File

	initDownload(filename);
	return 0;
}


char* replace(char* string, char replaceThis, char replaceWith)
{
	int l = strlen(string);
	int i;
	for (i = 0; i < l; ++i)
	{
		if(string[i] == replaceThis)
			string[i] = replaceWith;
	}
	return string;
}

char * sendMsg(char * msg, int wait) {
	msg = replace(msg,' ', '&');
	char returncode[1024];
	int ClientSocket = 0;
	struct sockaddr_in c_serv_addr;

	ClientSocket = socket(AF_INET,SOCK_STREAM,0);
	c_serv_addr.sin_family = AF_INET;
	c_serv_addr.sin_port = htons(portno);
	c_serv_addr.sin_addr.s_addr = inet_addr(IP);

	while(connect(ClientSocket,(struct sockaddr *)&c_serv_addr,sizeof(c_serv_addr))<0);
	bzero(buffer,1024);
	sscanf(msg, "%s", buffer);
	if(send(ClientSocket,buffer,strlen(buffer),0)<0) 
		printf("ERROR while writing to the socket\n");
	bzero(buffer,1024);
	if (wait == 1) {
		if(recv(ClientSocket,buffer,1024,0)<0)
			printf("ERROR while reading from the socket\n");
	 	sscanf(buffer, "%s", returncode);
		close(ClientSocket);
		return returncode;
	}

}

int initDownload(char * filename) {
	char returncode[1024];
	int ClientSocket = 0;
	int ret;
	char * decoded;
	int counter, idx;
	char c;
	char hashed[SHA_DIGEST_LENGTH];
	int i;
	long long int encrypted, decrypted;
	long long int fileSize;
	char encoded[5];
	struct sockaddr_in c_serv_addr;

	ClientSocket = socket(AF_INET,SOCK_STREAM,0);
	if(ClientSocket<0)
	{
		printf("ERROR WHILE CREATING A SOCKET\n");
		return 0;
	}
	c_serv_addr.sin_family = AF_INET;
	c_serv_addr.sin_port = htons(portno);
	c_serv_addr.sin_addr.s_addr = inet_addr(IP);

	while(connect(ClientSocket,(struct sockaddr *)&c_serv_addr,sizeof(c_serv_addr))<0);


	bzero(buffer,1024);
	sscanf(filename, "%s", buffer);
	if(send(ClientSocket,buffer,strlen(buffer),0)<0)
		printf("ERROR while writing to the socket\n");
	bzero(buffer,1024);
	strcat(filename, "_received");
	FILE *fp = fopen(filename+1, "wb");
	if(recv(ClientSocket,buffer,1024,0)<0)
		printf("ERROR while reading from the socket\n");
 	sscanf(buffer, "%s", returncode);
	if(returncode[0]=='x') {
		i=1;
		fileSize = 0;
		while(returncode[i]!='\0') {
	        fileSize *= 10;
	        fileSize += returncode[i++]-'0';
    	}
		bzero(buffer,1024);
		ret = 1;
		for (ret = 0; ret<fileSize/2; ret++)
		{
			bzero(buffer,1024);
			recv(ClientSocket,buffer,1024,0);

			bzero(hashed, 20);

			idx=0;
			counter = 0;
			c = buffer[idx];	
			encrypted = 0;
			while (c!=':') {
				encrypted = encrypted + (c - '0');
				encrypted = encrypted * 10;
				idx++;
				counter++;
				c = buffer[idx];
			}
			encrypted = encrypted/10;
			decrypted = Decryption(encrypted, private);

			if (decrypted < 10) {
				sprintf(encoded, "0%lld", decrypted);
			}
			else {
				sprintf(encoded, "%lld", decrypted);
			}
			decoded = decode_string(encoded);
			fwrite(decoded, sizeof(char),strlen(decoded), fp);
			printf("Received [ %d of %d ] ...\r", ret+1, fileSize/2);
		}
		printf("\n");
		bzero(buffer,1024);
		fclose(fp);
	}
	printf("File download complete.\n");
	printf("Closing Connection\n");
	close(ClientSocket);
	return 1;
}


char *decode_string(char *text)
{
    char dec[2];
    char *send = (char *)malloc(sizeof(char) * 400000);
    int size = 0;
    int make;

    if(text == NULL)
        return NULL;
    int i;
    
    for(i = 0; i < strlen(text); i += 2)
    {
        dec[0] = text[i];
        dec[1] = text[i + 1];
        make = (((int)dec[0] - '0') * 10) + ((int)dec[1] - '0');
        if(make == 0)
            send[size++] = ' ';
        else if((make >= 1) && (make <= 25))
            send[size++] = 'A' + make - 1;
        else if((make >= 26) && (make <= 51))
            send[size++] = (make - 26) + 'a';
        else if((make >= 52) && (make <= 61))
            send[size++] = (make - 52) + '0';
        else if(make == 62)
            send[size++] = ',';
        else if(make == 63)
            send[size++] = '.';
        else if(make == 64)
            send[size++] = '!';
    }
    send[size++] = '\0';
    return send;
}
