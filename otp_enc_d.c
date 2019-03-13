#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

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
 * Name: ValidateSource()
 * Description:
 * ************************************************************************/
void ValidateSource(int socket){
  int r = 0,
      s = 0;
  char valid[7],
       denied[6] = "denied",
       accept[6] = "accept";
  memset(valid, '\0', 7);
  
  while(r < 6)
  {
    r = recv(socket, valid, 6, 0);
  }

   //if auth invalid
   if(strcmp(valid, "encode") != 0)
   {
     //respond that permission is denied
     while(s < 6)
     {
       s = send(socket, denied, 6, 0);
     }

     //exit child process
     fprintf(stderr, "otp_enc_d: only opt_enc is allowed to use this connection\n");
     exit(1);
   }
   //if auth is valid
   else
   {
      //respond permission granted
      while(s < 6)
     {
       s = send(socket, accept, 6, 0);
     }
   }
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
