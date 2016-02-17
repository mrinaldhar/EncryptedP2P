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
#include <stdlib.h>
#include <ctype.h>
#include <openssl/sha.h>
#include "RSA.c"

int listenSocket = 0;
int connectionSocket = 0;
char buffer[1024];
struct sockaddr_in s_serv_addr;
int portno = 5005;
char IP[25];
char perm;
key_pair public, private;


void initServer();
char* replace(char *, char, char);
char *readFile(FILE *);


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

int main() {
	listenSocket = socket(AF_INET,SOCK_STREAM,0);
		strcpy(IP, "127.0.0.1");
	printf("Socket created\n");
	initServer();
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


void initServer() {
	char filename[50];
	int filesize;
	long long int plaint, ciphert;
	char encrypted[20];
	char encoded[20];
	char hashed[SHA_DIGEST_LENGTH];
	char fbuffer[1024];
	char * encoded_file;
	char e_recv[10];
	int idx, counter;
	char c;
	char n_recv[10];
	struct stat obj;
	perm = 'n';
	// Its a general practice to make the entries 0 to clear them of malicious entry
	bzero((char *) &s_serv_addr,sizeof(s_serv_addr));
	

	s_serv_addr.sin_family = AF_INET;	//For a remote machine
	s_serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	s_serv_addr.sin_port = htons(portno);

	int yes=1;

if (setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
    perror("setsockopt");
}

	bind(listenSocket,(struct sockaddr * )&s_serv_addr,sizeof(s_serv_addr));
	if(listen(listenSocket,10) == -1)	//maximum connections listening to 10
	{
		printf("[SERVER] FAILED TO ESTABLISH LISTENING \n\n");
	}

	printf("Connection created. Listening on port %d\n", portno);

while((connectionSocket=accept(listenSocket , (struct sockaddr*)NULL,NULL))<0);

	bzero(buffer,1024);
	if(recv(connectionSocket,buffer,1024,0)<0)
		printf("ERROR while reading from Client\n");
	strcpy(buffer, replace(buffer,'&',' '));
	// printf("REQUEST: %s\n", buffer);

	switch(buffer[0]) {
		case 'k':

			bzero(e_recv, 10);
			bzero(n_recv, 10);

			idx=1;
			counter = 0;
			c = buffer[idx];	
			while (c!=':') {
				e_recv[counter] = c;
				idx++;
				counter++;
				c = buffer[idx];
			}
			idx++;
			c = buffer[idx];
			public.public_key.n = 0;	
			while (c!='\0') {
				public.public_key.n = public.public_key.n + (c - '0');
				public.public_key.n = public.public_key.n * 10;
				idx++;
				c = buffer[idx];
			}
			public.public_key.n = public.public_key.n / 10;
			public.public_key.e = atoi(e_recv);
			printf("Key received %lld %lld !\n", public.public_key.e, public.public_key.n);
			break;
		case 'd':
			bzero(hashed, SHA_DIGEST_LENGTH);

			sscanf(buffer+1, "%s", filename);
			
			FILE *fp = fopen(filename, "rb");

			bzero(buffer,1024);

			printf("File requested: %s\n", filename);

			encoded_file = readFile(fp);
			filesize = strlen(encoded_file);

			buffer[0]='x';
			sprintf(buffer+1, "%d", filesize);
			send(connectionSocket,buffer,1024,0);

			idx = 0;
			c = encoded_file[0];
			for (idx=0; idx<filesize; idx+=2) {
				c = encoded_file[idx];
				plaint = 10 * (c - '0');
				c = encoded_file[idx+1];
				plaint = plaint + (c - '0');
				ciphert = Encryption(plaint, public);
				sprintf(encrypted, "%lld", ciphert);
				sprintf(encoded, "%lld", plaint);
				get_hash(encoded, hashed);
				sprintf(buffer, "%s:%s", encrypted, hashed);
				send(connectionSocket,buffer,1024,0);
			}
			break;
}

	close(connectionSocket);
	initServer();
}

char *readFile(FILE *fp)
{
    int size = 0;
    int seq_size = 0;
    int c;
    int enc;
    int digl, digr;
    char *ch;
    char *seq;
    char *enq;
    char found;

    if (fp == NULL)
        return NULL;

    ch = (char *)malloc(sizeof(char) * 400000);
    seq = (char *)malloc(sizeof(char) * 1600000);

    while((c = fgetc(fp)) != EOF)
    {
        ch[size++] = (char) c;
        found = (char) c;
        if (found == ' ' || found == ',' || found == '.' || found == '!')
        {
            //printf("yes\n");
            switch(found)
            {
                case ' ' : seq[seq_size++] = '0';
                           seq[seq_size++] = '0';
                           break;
                case ',' : seq[seq_size++] = '6';
                           seq[seq_size++] = '2';
                           break;
                case '.' : seq[seq_size++] = '6';
                           seq[seq_size++] = '3';
                           break;
                case '!' : seq[seq_size++] = '6';
                           seq[seq_size++] = '4';
                           break;
            }
        }
        else
        {
            if(islower(c))
            {
                enc = found - 'a' + 26;
                digl = enc % 10;
                digr = (enc / 10) % 10;
                seq[seq_size++] = (char) (digr + '0');
                seq[seq_size++] = (char) (digl + '0');
                //printf("%d ", enc);    
            }
            else if(isupper(c))
            {
                enc = found - 'A' + 1;
                if(enc < 10)
                {
                    digl = 0;
                    digr = enc;
                    seq[seq_size++] = (char) (digl + '0');
                    seq[seq_size++] = (char) (digr + '0');
                }
                else
                {
                    digl = enc % 10;
                    digr = (enc / 10) % 10;
                    seq[seq_size++] = (char) (digr + '0');
                    seq[seq_size++] = (char) (digl + '0');
                }
                //printf("%d ", enc);
            }
            else if(isdigit(c))
            {
                enc = found - '0' + 52;
                digl = enc % 10;
                digr = (enc / 10) % 10;
                seq[seq_size++] = (char) (digr + '0');
                seq[seq_size++] = (char) (digl + '0');
                //printf("%d ", enc);
            }
        }
    }
           
    seq[seq_size++] = '\0';     
    return seq;
}
