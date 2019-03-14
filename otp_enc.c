#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define RESP_SIZE 70000

void ProcessFiles(int, char*, char*);
void GetAuth(int);
int FileSize(int, char*);
char* FileToArray(char*, int, FILE*);
void CheckChars(int, int, char[]);
void SendMsg(int, char*, int);
char* RecMsg(int, char*);
void SendFile(int, int, char*);


int main(int argc, char *argv[])
{
  int socketFD,
      portNum,
      chWrit, 
      chRead;
  struct sockaddr_in servAdd;
  struct hostent* sHostInfo;
  memset((char*)&servAdd, '\0', sizeof(servAdd));
 
  //check enough args were given
  if (argc < 4) 
  {
      fprintf(stderr,"otp_enc: too few arguments were given\n"); 
      exit(2); 
   }

  // Set up the server address struct
  portNum = atoi(argv[3]); 
  servAdd.sin_family = AF_INET; 
  servAdd.sin_port = htons(portNum); 
  sHostInfo = gethostbyname("localhost"); 

  if (sHostInfo == NULL) 
  { 
    fprintf(stderr, "otp_enc: no such host exists\n"); 
    exit(2); 
  }
	
  //copy in host info
  memcpy((char*)&servAdd.sin_addr.s_addr, (char*)sHostInfo->h_addr, sHostInfo->h_length); 

  //create the socket
  socketFD = socket(AF_INET, SOCK_STREAM, 0); 
  if (socketFD < 0) 
  {
    fprintf(stderr, "otp_enc: error opening socket\n");
    exit(2);
  }	

  // Connect to server
  if (connect(socketFD, (struct sockaddr*)&servAdd, sizeof(servAdd)) < 0)
  {
    fprintf(stderr, "otp_enc: error connecting to server\n");
    exit(2);
  }

  //make sure authorized to connect
  GetAuth(socketFD);
 
  //send plaintext
  SendPlaintxt(socketFD, argv[1]);
  
  //send key
  SendKey(txtSize, socketFD, argv[2]);
  
  return 0;
}


/**************************************************************************
 * Name: GetAuth()
 * Description:
 * ***********************************************************************/
void ProcessFiles(int, char*, char*){

}


/**************************************************************************
 * Name: GetAuth()
 * Description:
 * ***********************************************************************/
void GetAuth(int socket){
  char auth[6] = "encode";
  char* resp = calloc(RESP_SIZE, sizeof(char));
  memset(resp, '\0', RESP_SIZE);

  //send auth code
  SendMsg(socket, auth, 6);

  //recieve response (accept or denied)
  resp = RecMsg(socket, resp);
  
  printf("in GetAuth. resp: %s\n", resp);
  //if response is denied
  if(strcmp(resp, "denied") == 0)
  {
    fprintf(stderr, "otp_enc: this script isn't authorized to access this port\n");
    close(socket);
    exit(2);
  }

  //free alloc mem
  free(resp);
}


/**************************************************************************
 * Name: FileSize()
 * Description:
 * ***********************************************************************/
int FileSize(int socket, char* file){
  int len = 0;
  FILE *fp = NULL;

  fp = fopen(file,"r");
  if(fp == NULL)
  {
    fprintf(stderr, "otp_enc: couldnt open plaintext file\n");
    close(socket);
    exit(1);
  }

  fseek(fp, 0, SEEK_END);
  len = ftell(fp);
   
  return len;
}


/**************************************************************************
 * Name: FileToArray()
 * Description:
 * ***********************************************************************/
char* FileToArray(char* array, int len, FILE* file){
  int c = 0,
      i = 0;

  //transfer chars from file to array
  for(i; i < (len - 1); i++)
  {
    c = fgetc(file);
    array[i] = c;
  }
  
  return array;
}


/**************************************************************************
 * Name: CheckChars()
 * Description:
 * ***********************************************************************/
void CheckChars(int socket, int len, char txt[]){
  char valid[28] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
  int i = 0,
      j = 0,
      inBounds = 0;

  //loop through plaintext
  for(i; i < (len - 1); i++)
  {
    inBounds = 0;
    j = 0;
    for(j; j < 27; j++)
    {
       //char is valid
       if(txt[i] == valid[j])
       {
         inBounds = 1;
         break;
       }
    }
    
    //found an invalid char
    if(inBounds == 0)
    {
      fprintf(stderr, "otp_enc: plaintext file contains invalid character: %c\n", txt[i]);
      close(socket);
      exit(1);
    }
  }
 
}


/**************************************************************************
 * Name: SendMsg()
 * Description:
 * ***********************************************************************/
void SendMsg(int socket, char* msg, int size){
   int s = 0,
       loop = size; 
    
  //loop until full message sent
  while(s < loop)
  {
    s = send(socket, msg, size, 0);
    //move pointers based on what successfully sent
    size =- s;
    msg += s;
   
    //if error
    if(s == -1)
    {
      fprintf(stderr, "enc_c: error sending message\n");
      exit(2);
    }
  }
}

/**************************************************************************
 * Name: RecMsg()
 * Description:
 * ***********************************************************************/
char* RecMsg(int socket, char* msg){
  int r = 0,
      full = 1;
  char rec[20];
  memset(rec, '\0', 20);
  
  do{
     r = recv(socket, rec, 20, 0);
     //if receive buffer isn't full
     if(r != 20)
       full = 0;
 
    //if error
    if(r == -1)
    {
      fprintf(stderr, "enc_c: error receiving message\n");
      exit(2);
    }
    strcat(msg, rec);
    printf("in rec msg loop. msg: %s\n", msg);
  }while(full);

  return msg;
}


/**************************************************************************
 * Name: SendPlaintxt()
 * Description:
 * ***********************************************************************/
void SendFile(int socket, int len, char* txt){
  FILE *fp;
  char *farray =  calloc (len, sizeof(char));
  memset(farray, '\0', len);
 
  //open file
  fp = fopen(txt, "r");
  if(fp == NULL)
  {
    fprintf(stderr, "otp_enc: couldn't open file: %s\n", fp);
    close(socket);
    exit(1);
  }
  
  farray = FileToArray(farray, len, fp);  //read file to array
  CheckChars(socket, len, farray);  //check that all chars given are valid

  //send file 
  SendMsg(socket, farray, len);
  
  //close file and free alloc mem
  fclose(fp);
  free(farray);
  return len;
}


