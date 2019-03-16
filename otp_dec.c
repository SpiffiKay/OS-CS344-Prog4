#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define RESP_SIZE 75000

void GetAuth(int);
void ProcessFiles(int, char*, char*);
void SendFile(int, int, char*);
void SendMsg(int, char*, int);
char* RecMsg(int, char*);
void SendFile(int, int, char*);
int FileSize(int, char*);
char* FileToArray(char*, int, FILE*);
void CheckChars(int, int, char*);
void CompSize(int, int, int);


int main(int argc, char *argv[])
{
  int socketFD,
      port;
  struct sockaddr_in sadd;
  struct hostent* hostinfo;
  memset((char*)&sadd, '\0', sizeof(sadd));

  //check enough args were given
  if (argc < 4)
  {
      fprintf(stderr,"otp_enc: too few arguments were given\n");
      exit(2);
   }

  // Set up the server address struct
  port = atoi(argv[3]);
  sadd.sin_family = AF_INET;
  sadd.sin_port = htons(port);
  hostinfo = gethostbyname("localhost");

  if (hostinfo == NULL)
  {
    fprintf(stderr, "otp_enc: no such host exists\n");
    exit(2);
  }

  //copy in host info
  memcpy((char*)&sadd.sin_addr.s_addr, (char*)hostinfo->h_addr, hostinfo->h_length);

  //create the socket
  socketFD = socket(AF_INET, SOCK_STREAM, 0);
  if (socketFD < 0)
  {
    fprintf(stderr, "otp_enc: error opening socket\n");
    exit(2);
  }

  // Connect to server
  if (connect(socketFD, (struct sockaddr*)&sadd, sizeof(sadd)) < 0)
  {
    fprintf(stderr, "otp_enc: error connecting to server\n");
    exit(2);
  }

  //make sure authorized to connect
  GetAuth(socketFD);

  //communicate with server
  ProcessFiles(socketFD, argv[1], argv[2]);

  close(socketFD);
  return 0;
}


/**************************************************************************
 * Name: GetAut()
 * Description: Takes the socket used to communicate with the server as a
 * param. Sends "encode" to server to identify self as otp_enc_c and
 * request authorization. The server responds that authorization is either
 * accepted or denied. If accepted, the program continues, if denied, the
 * socket is closed, and the program is exited.
 * ***********************************************************************/
void GetAuth(int socket){
  char auth[] = "decode&";
  char* resp = calloc(RESP_SIZE, sizeof(char));
  memset(resp, '\0', RESP_SIZE);

  //send auth code
  SendMsg(socket, auth, 7);

  //recieve response (accept or denied)
  resp = RecMsg(socket, resp);

  //if response is denied
  if(strcmp(resp, "denied") == 0)
  {
    fprintf(stderr, "otp_dec: this script isn't authorized to access this server\n");
    close(socket);
    exit(2);
  }

  //free alloc mem
  free(resp);
}


/**************************************************************************
 * Name: ProcessFiles()
 * Description: Takes the socket used to communicate with the server as a
 * param. Also takes char arrays holding the plaintext and key filenames
 * that were given by user from the command line as params. First, finds
 * the file size (# of chars) of both files and sends the lengths to be
 * compared. If the key is shorter than the plaintext file, the program
 * will be terminated. If not, The files are are send to SendFile to go
 * through further vetting and to be send to the server. Finally, an
 * decoded version of plaintext is received and printed to screen.
 * ***********************************************************************/
void ProcessFiles(int socket, char* text, char* key){
  int tlen = 0,
      klen = 0;
  char* decoded = calloc(RESP_SIZE, sizeof(char));
  memset(decoded, '\0', RESP_SIZE);

  //get the length of files and compare length
  tlen = FileSize(socket, text);  //plaintext
  klen = FileSize(socket, key);   //key
  CompSize(socket, tlen, klen);

  //validate and send plaintext and key
  SendFile(socket, tlen, text);
  SendFile(socket, klen, key);

  //receive decoded message and print to screen
  decoded = RecMsg(socket, decoded);

  printf("%s\n", decoded);
  fflush(stdout);

  //free alloc mem
  free(decoded);
}


/**************************************************************************
 * Name: SendFile()
 * Description: Takes the socket used to communicate with the server as a
 * param. It also takes a char array holding a file name, and the file
 * length, as parameters. The file is opened, then the contents are
 * transfered to an array. The array is checked to make sure it is composed
 * of valid chars ('A-Z' and ' '), then the message is sent to the server.
 * ***********************************************************************/
void SendFile(int socket, int len, char* txt){
  FILE *fp;
  char *farray =  calloc (len+1, sizeof(char));
  memset(farray, '\0', len+1);

  //open file
  fp = fopen(txt, "r");
  if(fp == NULL)
  {
    fprintf(stderr, "otp_dec: couldn't open file: %s\n", fp);
    close(socket);
    exit(1);
  }

  farray = FileToArray(farray, len, fp);  //read file to array
  CheckChars(socket, len, farray);  //check that all chars given are valid

  //add EOT and send file
  strcat(farray, "&");
  SendMsg(socket, farray, len+1);

  //close file and free alloc mem
  fclose(fp);
  free(farray);
}


/**************************************************************************
 * Name: SendMsg()
 * Description: Takes the socket used to communicate with the server as a
 * param. Also takes a char array holding the message to be sent, and the
 * size of that array, as params. It then sends messages to the server.
 * ***********************************************************************/
void SendMsg(int socket, char* msg, int size){
  int s = 0,
      i = 0;

 //loop until full message sent
 do
 {
   s = send(socket, msg+i, size, 0);
   //move pointers based on what successfully sent
   i += s;

   //if error
   if(s == -1)
   {
     fprintf(stderr, "otp_dec: error sending message\n");
     exit(2);
   }
 }while(i < size);
}


/**************************************************************************
 * Name: RecMsg()
 * Description: Takes the socket used to communicate with the server as a
 * param. Also takes an empty char array to store the received message in.
 * This function receives a message from the server it is connected to,
 * 20 chars at a time, and concatenates that chunk of the message to the
 * char array passed to the function. Once the amount of chars sent is
 * < 20, it is known that the message is finished sending, and the loop
 * ends. The received message is then returned.
 ***********************************************************************/
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
 * Name: FileSize()
 * Description: Takes the socket used to communicate with the server as a
 * param. Also takes a char array that holds a file name as a param. It
 * opens the file, finds the length of the file, and returns it.
 * ***********************************************************************/
int FileSize(int socket, char* file){
  int len = 0;
  FILE *fp = NULL;

  //open file
  fp = fopen(file,"r");
  if(fp == NULL)
  {
    fprintf(stderr, "otp_dec: couldnt open file: %s\n", fp);
    close(socket);
    exit(1);
  }

  //get length of file
  fseek(fp, 0, SEEK_END);
  len = ftell(fp);

  fclose(fp);

  return len;
}


/**************************************************************************
 * Name: FileToArray()
 * Description: Takes an empty char array to hold file contents, and a
 * file pointer pointing to file to be worked with as params. It then
 * cycles through to move the contents of the file to the array, one char
 * at a time. Finally, the array is returned.
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
 * Description:  Takes the socket used to communicate with the server as a
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
      fprintf(stderr, "otp_dec: file contains invalid character: txt[%d]: %d %c\n", i, txt[i], txt[i]);
      close(socket);
      exit(2);
    }
  }

}


/**************************************************************************
 * Name: CompSize()
 * Description: Takes the socket used to communicate with the server as a
 * param. Also takes the length of the plaintext file and the key file.
 * It compares the length of both, and if key is shorter than plaintext
 * the socket is closed and the program is exited. Otherwise, the program
 * continues.
 * ***********************************************************************/
void CompSize(int socket, int txt, int key){
  //if key is too short
  if(key < txt)
  {
    fprintf(stderr, "otp_dec: key is too short\n");
    close(socket);
    exit(2);
  }
}
