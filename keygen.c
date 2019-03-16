/**************************************************************************
 * Title: keygen.c							  *
 * Name: Tiffani Auer							  *
 * Due: Mar 18, 2019							  *
 * Description: This program generates a randomized key of the length	  *
 * given by the user.							  *
 * ***********************************************************************/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


void Validate(int, int);
void GetKey();


int main(int argc, char* argv[]){
  srand(time(0));  //seeding rand
  int len = 0,
      i = 0;
 
  //get value given into int var (if exists)
  if(argc >= 2)
    len = atoi(argv[1]);
  
  //make sure key length is given and valid
  Validate(argc, len);

  //Generate Key
  for(i; i < len; i++)
  {
    GetKey();
  }
  
  //add newline to the end of key;
  printf( "\n");
  fflush(stdout); 
   
   return 0;
}


/**************************************************************************
 * Name: Vanidate()
 * Description: Takes the numbers of args from the command line, as well as
 * the length of key to be made, given by user (if one was given). If no 
 * argument was given an error is written to stderr, and program exits. If
 * an argument is giveb, the argument is then tested to make sure it is 
 * valid (1 or greater). If it is invalid, an error message is printed to 
 * stderr, and the program exits.
 * ***********************************************************************/
void Validate(int argc, int len){
 
  //if there's no key length given, error
  if(argc < 2)
  {
    fprintf(stderr, "The key length was not provided.\n");
    exit(1);
  }
  
  //if key length is less than 1, error
  if(len < 1)
  {
    fprintf(stderr, "Invalid key length.\n");
    exit(1);
  }
}


/**************************************************************************
 * Name: GetRand()
 * Description: Generates a random number within the given range using 
 * getrand() *while not best for real life encryption standards, it does 
 * for assignment specs*, then prints the ASCII char to screen. 
 *
 * NOTE: Allowable chars are uppercase A-Z and ' ', but ' ' is not next to
 * A-Z on the ASCII table. Instead, allowed the # for '@' which is next to 
 * A-Z, and when it is selected, it is switched out for ' ' to rectify this
 * problem.
 * ***********************************************************************/
void GetKey(){
  int letter = 0;
 
  //found how to stay within range here:https://stackoverflow.com/questions/1202687/how-do-i-get-a-specific-range-of-numbers-from-rand
  letter = rand() % (90 + 1 - 64) + 64;
  
  //change '@' to ' '
  if(letter == 64)
    letter = 32;
 
  //print ASCII char to screen as part of key 
   printf("%c", letter);
   fflush(stdout);
}
