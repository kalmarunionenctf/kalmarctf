// "CycleChaser" and "CycleChaser Revenge" challenge for KalmarCTF 2023
// Original idea to make a challenge involving inverting Collatz by killerdog
// Concept for the challenge by killerdog and shalaamum
// Implementation by shalaamum

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <string.h>
#include <sys/random.h>

#ifdef DEBUG
#define TIMEOUT 300
#define SEQUENCELEN_RANDOM 1024
#define RANDOMBYTES 16
#define FLAGLEN 32
#else
#define TIMEOUT 300
#define SEQUENCELEN_RANDOM 131072
#define RANDOMBYTES 1024
#define FLAGLEN 64
#endif

// Set this to get the revenge version
// Probably with -D REVENGE
//#define REVENGE

// At first we xor with random stuff, and at then end with the flag if we have
// odd steps. This forces the user to end with a bunch of odd steps, so in the
// easy version of the chal only even and at the end odd will work.
#define SEQUENCELEN (SEQUENCELEN_RANDOM + FLAGLEN)
// For a prescribed sequence of odd/even of length there is exactly one number
// < 2**n whose Collatz sequence has those steps.
// So the start number should have the same number of bits as the sequence
// length.  Overflows will not be allowed, so the user will have to ensure that
// there are enough even steps, particularly at the start.
// We add an extra byte because we are nice.
#define VALUEBYTES ((SEQUENCELEN / 8) + 1)

#define ERRORMSG "Error.\n"


#define FLAGPREFIX "kalmar{"
#define FLAGSUFFIX "}"


void timer_callback(int signum)
{
  printf("Out of time.\n");
  exit(1);
}

unsigned char step(unsigned char* value, unsigned int length)
{
  // Carries out one Collatz step and returns true iff this was an odd step.
  // The bytes are ordered in little endian order the bits in a byte are
  // ordered in big endian order.
  unsigned char result;
  // We first check whether the value is odd
  result = value[0] & 1; 
  if(result)
  {
    // odd case, so need to replace value with (3*value) + 1
    // dividing by 2 will be done in either case afterwards.
    // tmp is the carry from previous byte, and starts with 1
    // due to the "+ 1".
    unsigned long tmp = 1;
    unsigned long new_tmp = 0;
    for(unsigned int i = 0; i < length; i++)
    {
      new_tmp = (unsigned long)value[i];
      new_tmp *= 3;
      // new_tmp is now the byte, shifted appropriately,
      // multiplied by 3
      new_tmp += tmp;
      // Now we also added the carry.
      // We now extract the carry for the next step
      tmp = new_tmp >> 8;
      // Finally, we update the value at that byte
      new_tmp &= 0xFF;
      value[i] = (unsigned char)new_tmp;
    }
    // tmp is the left over carry. If it is non-zero, there is an overflow.
    if(tmp)
    {
      printf(ERRORMSG);
#ifdef DEBUG
      printf("Overflow\n");
#endif
      exit(99);
    }
  }
  // in both cases need to replace value with value / 2
  unsigned char extra = 0;
  unsigned char new_extra;
  for(signed int i = length - 1; i >= 0; i--)
  {
    new_extra = value[i] & 1;
    value[i] >>= 1;
    value[i] |= (extra * 0x80);
    extra = new_extra;
  }
  assert(extra == 0);
  return result;
}

int main()
{
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
#ifdef DEBUG
  //printf("Running in debug mode\n");
#endif
//#ifdef DEBUG
//  unsigned char * testval = calloc(4,1);
//  testval[0] = 7;
//  testval[1] = 1;
//  while(testval[0] != 1)
//  {
//    printf("%i: ", *((unsigned int*)testval));
//    printf("%i\n", step(testval,4));
//  }
//  exit(0);
//#endif

  // We want this to hold because of the overflow check.
  // We require the user to give a startnumber and will constrain what the user
  // will want the odd/even steps of the Collatz sequence starting with that
  // number to be.  The required number might have about as many bits as the
  // length of the sequence, but the values reached in the sequence are not
  // allowed to have more bits.  As odd steps multiply by roughly 3/2 and even
  // ones by 1/2 it must be possible to construct a start number with a
  // sequence with the required other properties such that there are
  // sufficiently many even steps.
  // We will require that each of the random bytes will fall on even steps
  // maximum FLAGLENGTH times. The condition below means that each random byte
  // will occur 2*FLAGLENGTH times, so the requirement will mean that up to
  // roughly half of the steps are allowed to be even, which means up to some
  // constraints at the start the values should fall so that the limited width
  // available for the values should not pose a problem.
  assert(SEQUENCELEN_RANDOM / RANDOMBYTES == 2 * FLAGLEN);

  // Set up the structure for the SIGALARM signal
  struct sigaction alarm_action;
  alarm_action.sa_handler = timer_callback;
  sigemptyset(&alarm_action.sa_mask);
  alarm_action.sa_flags = 0;

  // Make SIGALARM call the timer_callback function
  sigaction(SIGALRM, &alarm_action, NULL);

  // Set a alarm that will cause the program to quit when after TIMEOUT seconds
  alarm(TIMEOUT);

  // Get a random seed for the random number generator and communicate it to
  // the user
  unsigned int seed;
  if(getrandom(&seed, sizeof(seed), 0) != sizeof(seed))
  {
    printf(ERRORMSG);
    exit(2);
  }
  printf("%X\n", seed);
  srand(seed);

#ifdef DEBUG
  //printf("Gave the seed to the player, now allocating stuff\n");
#endif

  // Get a random buffer
  unsigned char * random = malloc(RANDOMBYTES);
  if(getrandom(random, RANDOMBYTES, 0) != RANDOMBYTES)
  {
    printf(ERRORMSG);
    exit(8);
  }


  // Read the flag
  FILE * flag_fp;
  flag_fp = fopen("./flag.txt", "r");
  if(!flag_fp)
  {
    printf(ERRORMSG);
    exit(3);
  }
  unsigned int flag_total_len = strlen(FLAGPREFIX) + FLAGLEN + strlen(FLAGSUFFIX);
  unsigned char * flag_full = malloc(flag_total_len + 1);
  if(!flag_full)
  {
    printf(ERRORMSG);
    exit(4);
  }
  if(fread(flag_full, 1, flag_total_len, flag_fp) != flag_total_len)
  {
    printf(ERRORMSG);
    exit(5);
  }
  fclose(flag_fp);

  //Assert some things about the flag so that the players know what to expect
  assert(!strncmp((char*)flag_full, FLAGPREFIX, strlen(FLAGPREFIX)));
  assert(!strncmp((char*)((long)flag_full + strlen(FLAGPREFIX) + FLAGLEN), FLAGSUFFIX, strlen(FLAGSUFFIX)));
  unsigned char * flag;
  flag = (unsigned char *)((long)(flag_full + strlen(FLAGPREFIX)));
  for(unsigned int i = 0; i < FLAGLEN; i++)
  {
    // only lowercase letters and underscore
    assert((0x5f <= flag[i]) && (flag[i] <= 0x7a));
  }
  

  // Read the start value from the user
#ifdef DEBUG
  //printf("Trying to read value from user, %i bytes\n", VALUEBYTES);
#endif
  unsigned char * value = malloc(VALUEBYTES);
  if(!value)
  {
    printf(ERRORMSG);
    exit(6);
  }
  if(fread(value, 1, VALUEBYTES, stdin) != VALUEBYTES)
  {
    printf(ERRORMSG);
    exit(7);
  }
#ifdef DEBUG
  //printf("Read value from user\n");
#endif

  unsigned char * flag_enc = calloc(FLAGLEN, 1);
  unsigned char v;
  unsigned int index;
  unsigned char should_xor = 0;

#ifdef REVENGE
  unsigned int * random_occ_count = calloc(sizeof(unsigned int)*RANDOMBYTES, 1);
  if(!random_occ_count)
  {
    printf(ERRORMSG);
    exit(20);
  }
  unsigned int * random_xor_count = calloc(sizeof(unsigned int)*RANDOMBYTES, 1);
  if(!random_xor_count)
  {
    printf(ERRORMSG);
    exit(21);
  }
  // flag_xor_count[flag_index] will store for each rand_index whether that
  // random byte was xored an odd number of times into this flag byte 
  unsigned char ** flag_xor_count = malloc(sizeof(unsigned char *)*FLAGLEN);
  if(!flag_xor_count)
  {
    printf(ERRORMSG);
    exit(22);
  }
  for(unsigned int i = 0; i < FLAGLEN; i++)
  {
    flag_xor_count[i] = calloc(RANDOMBYTES / 8, 1);
    if(!flag_xor_count[i])
    {
      printf(ERRORMSG);
      exit(23);
    }
  }
#endif

  // Now we actually run through the Collatz sequence starting from the
  // provided startvalue
  for(unsigned int i = 0; i < SEQUENCELEN; i++)
  {
    if(i < SEQUENCELEN_RANDOM)
    {
      // At the start what we xor will be one of the bytes from the random
      // buffer. The reason we use rand() % RANDOMBYTES here and not just
      // i % RANDOMBYTES is in order to ensure that players will need to
      // solve a fresh Collatz-inversion problem for each try.
      index = (unsigned int)rand() % RANDOMBYTES;
#ifdef REVENGE
      random_occ_count[index] += 1;
#endif
      v = random[index];
    }
    else
    {
      // For the last steps we xor in the flag.
      v = flag[i % FLAGLEN];
    }
    should_xor = step(value, VALUEBYTES);
    if(should_xor)
    {
      // We only xor on odd steps
      flag_enc[i % FLAGLEN] ^= v;
#ifdef REVENGE
      if(i < SEQUENCELEN_RANDOM)
      {
        random_xor_count[index] += 1;
        // update flag_xor_count
        flag_xor_count[i % FLAGLEN][index >> 3] ^= 1 << (index % 8);
      }
#endif
    }
  }

  #ifdef REVENGE
  // We require that each byte of the encrypted flag has been xored an odd
  // number of times by some random byte
  for(unsigned int flag_index = 0; flag_index < FLAGLEN; flag_index++)
  {
    unsigned char changed = 0;
    for(unsigned int j = 0; j < (RANDOMBYTES / 8); j++)
    {
      changed |= flag_xor_count[flag_index][j];
    }
    if(changed == 0)
    {
      printf(ERRORMSG);
#ifdef DEBUG
      printf("Flag byte %i has not been xored into!\n", flag_index);
#endif
      exit(10);
    }
  }
  // We also require that each random byte has been used at least
  // number of occurrences - FLAGLEN times
  for(unsigned int i = 0; i < RANDOMBYTES; i++)
  {
    if(random_xor_count[i] + FLAGLEN < random_occ_count[i])
    {
      printf(ERRORMSG);
#ifdef DEBUG
      printf("Random byte %i not used enough!\n", i);
#endif
      exit(11);
    }
  }
  #endif

  // Print out the flag
  for(unsigned int i = 0; i < FLAGLEN; i++)
  {
    printf("%0X ", flag_enc[i]);
  }
  printf("\n");

  // Cleanup
  free(random);
  free(flag_full);
  free(value);
  free(flag_enc);
#ifdef REVENGE
  free(random_xor_count);
  free(random_occ_count);
  for(unsigned int i = 0; i < FLAGLEN; i++)
  {
    free(flag_xor_count[i]);
  }
  free(flag_xor_count);
#endif
}
