#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

void GetAuth(int);
int FileSize(int, char*);
char* FileToArray(char*, int, FILE*);
void CheckChars(int, int, char[]);
void SendMsg(int, char*, int);
char* RecMsg(int, char*);
int SendPlaintxt(int, char*);
void SendKey(int, int, char*);

int main(int argc, char *argv[])
{
  int socketFD,
      portNum,
      chWrit, 
      chRead,
      txtSize;
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
  txtSize = SendPlaintxt(socketFD, argv[1]);
  
  //send key
  SendKey(txtSize, socketFD, argv[2]);
  
  return 0;
}


/**************************************************************************
 * Name: GetAuth()
 * Description:
 * ***********************************************************************/
void GetAuth(int socket){
  char auth[6] = "encode",
       resp[70000];
  memset(resp, '\0', 70000);

  //send auth code
  SendMsg(socket, auth, 6);

  //recieve response (accept or denied)
  resp = RecMsg(socket, resp);

  //if response is denied
  if(strcmp(resp, "denied") == 0)
  {
    fprintf(stderr, "otp_enc: this script isn't authorized to access this port\n");
    close(socket);
    exit(2);
  }
}


/**************************************************************************
 * Name: FileCompare()
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
void SendMsg(int socket, int size, char* msg){
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
char* RecMsg(int socket, char* buffer){
    //if error
    if(r == -1)
    {
      fprintf(stderr, "enc_c: error receiving message\n");
      exit(2);
    }

  return buffer;
}


/**************************************************************************
 * Name: SendPlaintxt()
 * Description:
 * ***********************************************************************/
int SendPlaintxt(int socket, char* txt){
  int len = 0;
  FILE *fp;
  char *farray = NULL;
     
  //get file size
  len = FileSize(socket, txt);
  farray = calloc (len, sizeof(char));
  memset(farray, '\0', len);
 
  //open file
  fp = fopen(txt, "r");
  if(fp == NULL)
  {
    fprintf(stderr, "otp_enc: couldnt open plaintext file\n");
    close(socket);
    exit(1);
  }
  
  farray = FileToArray(farray, len, fp);  //read file to array
  CheckChars(socket, len, farray);  //check that all chars given are valid

  //send file 
  SendMsg(socket, len, farray);
  
  //close file and free alloc mem
  fclose(fp);
  free(farray);
  return len;
}

/**************************************************************************
 * Name: SendKey()
 * Description:
 * ***********************************************************************/
void SendKey(int keysize, int socket, char* key){

}
