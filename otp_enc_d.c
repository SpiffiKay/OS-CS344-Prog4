#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#define RESP_SIZE 70000

void SendMsg(int, char*, int);
char* RecMsg(int, char*);
void ValidateSource(int);
void ProcessInfo(int);
void Encode(int);
void ReadPlaintxt(int);
void ReadKey(int);


int main(int argc, char *argv[])
{
  int listnSock,
      portNum, 
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
  portNum = atoi(argv[1]); 
  servAdd.sin_family = AF_INET; 
  servAdd.sin_port = htons(portNum); 
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
    fprintf(stderr, "otp_enc_d: error binding socket to port %d\n", portNum);
    exit(2);
  }

  //listen for client port connections	(can accept up to 5)
  if(listen(listnSock, 5) == -1)
  {
    fprintf(stderr, "otp_enc_d: unable to listen on port %d\n", portNum);
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
 *  * Name: SendMsg()
 *   * Description:
 *    * ***********************************************************************/
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
      {                                                                                              fprintf(stderr, "enc_c: error receiving message\n");
        exit(2);
      }                                                                                            strcat(msg, rec);                                                                            printf("in rec msg loop. msg: %s\n", msg);
   }while(full);
                                                                                                return msg;
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
     exit(1);
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
  //receive plaintext and keygen files
  ReadPlaintxt(socket);
  ReadKey(socket);

  //encrypt file to stdout
  Encode(socket);
}


/**************************************************************************
 * Name: ReadPlaintxt()
 * Description:
 * ************************************************************************/
void ReadPlaintxt(int socket){
}


/**************************************************************************
 * Name: ReadKey()
 * Description:
 * ************************************************************************/
void ReadKey(int socket){

}

/**************************************************************************
 * Name: Encode()
 * Description:
 * ************************************************************************/
void Encode(int socket){

}
