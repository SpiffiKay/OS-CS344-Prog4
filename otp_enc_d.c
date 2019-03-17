#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

#define RESP_SIZE 75000

//global variable so I don't give up on life
int COUNT_THE_CHILDREN = 0;

void ValidateSource(int);
void ProcessInfo(int);
void SendMsg(int, char*, int);
char* RecMsg(int, char*);
void CheckChars(int, int, char*);
void Encode(int, char*, char*);
void dedChild(int);

int main(int argc, char *argv[])
{
  pid_t bgPIDs[128];
  int childExit,
      numcnncts = 0,
      lsock,
      port,
      newsock,
      spawnPID = 0,
      i = 0,
      j = 0,
      k = 0;
  socklen_t cinfo;
  struct sockaddr_in servadd,
                     clientadd;
  memset((char *)&servadd, '\0', sizeof(servadd));

  //deal with SIGCHLD
  struct sigaction ded_child = {0};
  ded_child.sa_handler = dedChild;
  sigfillset(&ded_child.sa_mask);
  ded_child.sa_flags = SA_RESTART;
  sigaction(SIGCHLD, &ded_child, NULL);

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

    cinfo = sizeof(clientadd);
    //printf("PARENT # of connects: %d\n", newsock);
    newsock = accept(lsock, (struct sockaddr *)&clientadd, &cinfo); // Accept
    // Accept a connection, blocking if one is not available until one connects

    if (newsock < 0)
    {
      fprintf(stderr, "otp_enc_d: connection acception failed\n");
      exit(2);
    }
    else
      COUNT_THE_CHILDREN++;

       //create child processes
       if((spawnPID = fork()) == 0)
       //stop fork bombsf
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
             ValidateSource(newsock); //validate source is otp_enc, not otp_dec
             ProcessInfo(newsock); //encode message
             close(newsock);
             return 0;
             break;
         default:
             bgPIDs[j] = spawnPID;
             j++;

             while((spawnPID = waitpid(-1, &childExit, WNOHANG)) > 0)
             {
               COUNT_THE_CHILDREN--;
             }

             break;
       }
   }

  //close listening socket
  close(lsock);

  //murder zombies
  for(k; k < j; k++)
  {
    kill(bgPIDs[k], SIGTERM);
  }

  return 0;
}


/**************************************************************************
 * Name: ValidateSource()
 * Description: Takes the socket used to communicate with the client as a
 * param. Receives a message from the client. If it is exactly as expected,
 * responds with the accept message. If anything else is received, the
 * denied message is sent.
 * ************************************************************************/
void ValidateSource(int socket){
  char denied[] = "denied&",
       accept[] = "accept&";
  char* ptr = NULL;
  char valid[RESP_SIZE];
  memset(valid, '\0', RESP_SIZE);

  //printf("enc_d: in validate source\n");
//  fflush(stdout);

   //receive validation request
   ptr = RecMsg(socket, valid);
   sprintf(valid, ptr);

   //if auth invalid
   if(strcmp(valid, "encode") != 0)
   {
     SendMsg(socket, denied, 7);
     //exit child process
     close(socket);
     exit(2);
   }
   //if auth is valid
   else
     SendMsg(socket, accept, 7);
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
  char* tptr = NULL;
  char* kptr = NULL;
  char text[RESP_SIZE];
  char key[RESP_SIZE];
  memset(text, '\0', RESP_SIZE);
  memset(key, '\0', RESP_SIZE);

  //printf("enc_d: processinfo: ");
  //fflush(stdout);
  //receive plaintext and keygen files
  tptr = RecMsg(socket, text);
  kptr = RecMsg(socket, key);
  sprintf(text, tptr);
  sprintf(key, kptr);

  //make sure plaintext has no illegal chars
  len = strlen(text);
  CheckChars(socket, len, text);

  //printf("text len: %d ", len);
//  fflush(stdout);

  len = 0;
  len = strlen(key);
  CheckChars(socket, len, key);

  //printf("key len: %d\n", len);
//  fflush(stdout);
  //encrypt file to stdout
  Encode(socket, text, key);
}


/**************************************************************************
 * Name: SendMsg()
 * Description: Takes the socket used to communicate with the client as a
 * param. Also takes a char array holding the message to be sent, and the
 * size of that array, as params. It then sends messages to the client.
 * ***********************************************************************/
void SendMsg(int socket, char* msg, int size){
  int s = 0,
      i = 0,
      tosend = size;

    //  printf("dec: in sendmsg\n");
    //  fflush(stdout);

 //loop until full message sent
 while(i < size)
 {
   s = send(socket, msg+i, tosend, 0);
   //move pointers based on what successfully sent
   i += s;
   tosend -= s;

   //if error
   if(s == -1)
   {
     fprintf(stderr, "otp_dec: error sending message\n");
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
      i = 0,
      j = 0,
      end = 0;
 char buffer[RESP_SIZE];
 memset(buffer, '\0', RESP_SIZE);

  do
  {


      //receive message
      r = recv(socket, &buffer[i], RESP_SIZE - 1, 0);
      i += r;

          // printf("enc_d: recmsg loop: r: %d i: %d\n", r, i);
          // fflush(stdout);
      //if error
      if(r == -1)
      {
        fprintf(stderr, "otp_dec: error receiving message\n");
        close(socket);
        exit(2);
      }

      for(j; j < i; j++)
      {
        if(buffer[j] == '&')
        {
          end = 1;
          break;
        }
        msg[j] = buffer[j];
      }
  }while(end == 0 && i < RESP_SIZE);
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
  char valid[27] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
  int i = 0,
      j = 0,
      inBounds = 0;

   //printf("enc_d: checkchars\n");
  // fflush(stdout);

  //loop through message checking validity
  for(i; i < (len-1); i++)
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
      fprintf(stderr, "otp_dec_d: file contains invalid character: txt[%d]: %d %c\n", i, txt[i], txt[i]);
      close(socket);
      exit(1);
    }
  }
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
      j = 0,
      t = -1,
      k = -1;
  char abc[] = " ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  char* encoded = calloc(len+1, sizeof(char));
  memset(encoded, '\0', len+1);

  //printf("enc_d: in encode\n");
  //fflush(stdout);

  for(i; i < len; i++)
  {
    j = 0;
    t = -1;
    k = -1;
    //change from ASCII num to 1-27 so numbers don't go over 127  (ASCII limit)
    for(j; j < len; j++)
    {
      if(txt[i] == abc[j])
        t = j;
      if(key[i] == abc[j])
        k = j;
      if(t != -1 && k != -1)
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

  //add EOT char and send encrypted message to client
  strcat(encoded, "&");
  SendMsg(socket, encoded, len+1);
  //free alloc mem
  free(encoded);
}

//Deals with SIGCHLD signal. Keeps an accurate count of live children.
//I've been dealing with this problem for days, so my humor has gotten dark.
void dedChild(int signo){
  COUNT_THE_CHILDREN--;
}
