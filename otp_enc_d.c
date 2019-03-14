#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define RESP_SIZE 70000

void ValidateSource(int);
void ProcessInfo(int);
void SendMsg(int, char*, int);
char* RecMsg(int, char*);
void CheckChars(int, int, char*);
void Encode(int, char*, char*);

int main(int argc, char *argv[])
{
  int listnSock,
      port,
      chRead,
      cnnctFD,
      spawnPID = 0,
      i = 0;
  socklen_t cInfo;
  struct sockaddr_in servAdd,
                     clientAdd;
  memset((char *)&servAdd, '\0', sizeof(servAdd));

  //check if enough args included
  if (argc < 2)
  {
    fprintf(stderr,"otp_enc_d: invalid input\n");
    exit(2);
  }

  // Set up the address struct for the server
  port = atoi(argv[1]);
  servAdd.sin_family = AF_INET;
  servAdd.sin_port = htons(port);
  servAdd.sin_addr.s_addr = INADDR_ANY;

  // Set up the socket
  listnSock = socket(AF_INET, SOCK_STREAM, 0);
  if (listnSock < 0)
  {
    fprintf(stderr, "otp_enc_d: error creating socket\n");
    exit(2);
  }

  //bind socket to port
  if (bind(listnSock, (struct sockaddr *)&servAdd, sizeof(servAdd)) < 0)
  {
    fprintf(stderr, "otp_enc_d: error binding socket to port %d\n", port);
    exit(2);
  }

  //listen for client port connections	(can accept up to 5)
  if(listen(listnSock, 5) == -1)
  {
    fprintf(stderr, "otp_enc_d: unable to listen on port %d\n", port);
    exit(2);
  }

  //permanent while loop to keep server open
  while(1)
  {

    // Accept a connection, blocking if one is not available until one connects
    cInfo = sizeof(clientAdd);
    cnnctFD = accept(listnSock, (struct sockaddr *)&clientAdd, &cInfo); // Accept
    if (cnnctFD < 0)
      fprintf(stderr, "otp_enc_d: connection acception failed\n");

       //create child processes
       if((spawnPID = fork()) == 0)
          i++;
       //stop fork bombs
       if(i >= 50)
       {
         fprintf(stderr, "otp_enc_d: the forks are running wild!\n");
         exit(2);
       }

       switch(spawnPID)
       {
         case -1:
             fprintf(stderr, "otp_enc_d: Apparently you can't be trusted with forks.\n");
             break;
         case 0:
             ValidateSource(cnnctFD); //validate source is otp_enc, not otp_dec
             ProcessInfo(cnnctFD); //encode message
             break;
         default:
             break;
       }
   }

  //close listening socket
  close(listnSock);

  return 0;
}


/**************************************************************************
 * Name: ValidateSource()
 * Description:
 * ************************************************************************/
void ValidateSource(int socket){
  char denied[6] = "denied",
       accept[6] = "accept";
  char* valid = calloc(RESP_SIZE, sizeof(char));
  memset(valid, '\0', 70000);

   valid = RecMsg(socket, valid);

   //if auth invalid
   if(strcmp(valid, "encode") != 0)
   {
     SendMsg(socket, denied, 6);
     //exit child process
     fprintf(stderr, "otp_enc_d: only opt_enc is allowed to use this connection\n");
     exit(2);
   }
   //if auth is valid
   else
     SendMsg(socket, accept, 6);

  //free alloc mem
  free(valid);
}


/**************************************************************************
 * Name: ProcessInfo()
 * Description:
 * ************************************************************************/
void ProcessInfo(int socket){
  int len = 0;
  char* text = calloc(RESP_SIZE, sizeof(char));
  char* key = calloc(RESP_SIZE, sizeof(char));
  memset(text, '\0', RESP_SIZE);
  memset(key, '\0', RESP_SIZE);

  //receive plaintext and keygen files
  text = RecMsg(socket, text); 
  key = RecMsg(socket, key);

  //make sure plaintext has no illegal chars
  len = strlen(text);
  CheckChars(socket, len, text);

  //encrypt file to stdout
  Encode(socket, text, key);

  //free alloc mem
  free(text);
  free(key);
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
      {                                                                                              fprintf(stderr, "enc_d: error receiving message from client\n");
        exit(2);
      }                                                                                            strcat(msg, rec);                                                                     
   }while(full);
                                                                                                return msg;
}


/**************************************************************************
 *  * Name: CheckChars()
 *   * Description:
 *    * ***********************************************************************/
void CheckChars(int socket, int len, char* txt){
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
      exit(2);
    }                                                                                          }
}


/**************************************************************************
 * Name: Encode()
 * Description:
 * ************************************************************************/
void Encode(int socket, char* txt, char* key){ 
  int len = strlen(txt),
      i = 0,
      j = 0;
  char abc[28] = " ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  char* encoded = calloc(len, sizeof(char)),
        t = '\0',
        k = '\0';
  memset(encoded, '\0', len);

  for(i; i < len; i++)
  {

    j = 0;
    t = '\0';
    k = '\0';
    //change from ASCII num to 1-27 so numbers don't go over 127  (ASCII limit)
    for(j; j < len; j++)
    {
      if(txt[i] == abc[j])
        t = j;
      if(key[i] == abc[j])
        k = j;
      if(t != '\0' && k != '\0')
        break;
     }

    //encrypt
    encoded[i] = t + k + 64;
    //subtract if out of bounds 
    if(encoded[i] > 90)
       encoded[i] -= 27;
     //turn '@' to ' '
     if(encoded[i] == 64)
       encoded[i] = 32;
  }

  //send encrypted message to client
  SendMsg(socket, encoded, len);  
  //free alloc mem 
  free(encoded);   
}
