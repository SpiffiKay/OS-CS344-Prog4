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
  int lsock,
      port,
      cnnctFD,
      spawnPID = 0,
      i = 0;
  socklen_t cinfo;
  struct sockaddr_in servadd,
                     clientadd;
  memset((char *)&servadd, '\0', sizeof(servadd));

  //check if enough args included
  if (argc < 2)
  {
    fprintf(stderr,"otp_enc_d: invalid input\n");
    exit(2);
  }

  // Set up the address struct for the server
  port = atoi(argv[1]);
  servadd.sin_family = AF_INET;
  servadd.sin_port = htons(port);
  servadd.sin_addr.s_addr = INADDR_ANY;

  // Set up the socket
  lsock = socket(AF_INET, SOCK_STREAM, 0);
  if (lsock < 0)
  {
    fprintf(stderr, "otp_enc_d: error creating socket\n");
    exit(2);
  }

  //bind socket to port
  if (bind(lsock, (struct sockaddr *)&servadd, sizeof(servadd)) < 0)
  {
    fprintf(stderr, "otp_enc_d: error binding socket to port %d\n", port);
    exit(2);
  }

  //lsock for client port connections	(can accept up to 5)
  if(listen(lsock, 5) == -1)
  {
    fprintf(stderr, "otp_enc_d: unable to listen on port %d\n", port);
    exit(2);
  }

  //permanent while loop to keep server open
  while(1)
  {

    // Accept a connection, blocking if one is not available until one connects
    cinfo = sizeof(clientadd);
    cnnctFD = accept(lsock, (struct sockaddr *)&clientadd, &cinfo); // Accept
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

  //close lsocking socket
  close(lsock);

  return 0;
}


/**************************************************************************
 * Name: ValidateSource()
 * Description: Takes the socket used to communicate with the client as a 
 * param. Recieves a message from the client. If it is exactly as expected, 
 * responds with the accept message. If anything else is received, the
 * denied message is sent.
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
 * Description: Takes the socket used to communicate with the client as a 
 * param. Receives the plaintext and key messages from the client. It then 
 * finds the length of the messages and double checks the messages are 
 * composed of valid characters ('A-Z' and ' '). If valid, these messages are
 * then sent to encode to be used to encode the plaintext message.
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
  len = 0;
  len = strlen(key);
  CheckChars(socket, len, key);

  //encrypt file to stdout
  Encode(socket, text, key);

  //free alloc mem
  free(text);
  free(key);
}


/**************************************************************************
 * Name: SendMsg()
 * Description: Takes the socket used to communicate with the client as a 
 * param. Also takes a char array holding the message to be sent, and the 
 * size of that array, as params. It then sends messages to the client. 
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
* Description: Takes the socket used to communicate with the client as a 
* param. Also takes an empty char array to store the received message in.
* This function receives a message from the client it is connected to, 
* 20 chars at a time, and concatenates that chunk of the message to the 
* char array passed to the function. Once the amount of chars sent is 
* < 20, it is known that the message is finished sending, and the loop
* ends. The received message is then returned. 
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
 * Name: CheckChars()
 * Description: Takes the socket used to communicate with the client as a 
 * param. It also takes a char array holding the message, and the size of 
 * that array, as params. It then compares the passed array to an array of 
 * valid chars. If all the chars are valid the program continues. If not, 
 * the socket is closed and the program ends.
 * ***********************************************************************/
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
 * Description: Takes the socket used to communicate with the client as a 
 * param. Also takes char arrays holding the plaintext message and the key
 * sent from the client. An encoded message is built by adding the 
 * plaintext and key messages together, char by char. If a sum of 2 chars
 * goes out of bounds (>27), then the number is - 27 to find the correct 
 * value. 
 *
 * The encoded message is then sent to the client.
 *
 * NOTE: Because the ASCII values added  together cause problems when they
 * go above 127, they first are converted over to 1-27, added together, 
 * then converted back to their ASCII values.
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
