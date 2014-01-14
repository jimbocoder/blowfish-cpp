#include "blowfish.h"
#include <cstdlib>
#include <ctime>

BlowfishCipher::BlowfishCipher()
{
  // Randomize key
  uint32 hkey[14];
  srand(unsigned(time(NULL)));
  for(uint8 i=0; i<14; ++i)
  {
    hkey[i] = rand(); // 16 bit random
    hkey[i] <<= 16;
    hkey[i] |= rand();
  }
  SetKey(hkey);
    
  // Clear message buffer
  for(uint i=0; i < MAX_MSG_LEN/4; ++i)
  {
    buffer.halfblocks[i].binary = 0x00000000;
  }

}

BlowfishCipher::~BlowfishCipher()
{
}


uint32* BlowfishCipher::GetKey()
{
  return key;
}


func_status BlowfishCipher::SetKey(uint32 k[14])
{
  for(uint8 i=0; i<14; ++i)
    key[i]=k[i];
  InitializeSubkeys (key);
  return FUNC_STATUS_OK;
}


func_status BlowfishCipher::SetBuffer(char* buf)
{
  for(int i=0; i < MAX_MSG_LEN; ++i)
  {
    buffer.bytes[i] = buf[i];  
  }
  return FUNC_STATUS_OK;
}

func_status BlowfishCipher::SetBuffer(std::string str)
{
  for(int i=0; i < MAX_MSG_LEN; ++i)
  {
    buffer.bytes[i] = str[i];  
  }
  
  if (str.length() > MAX_MSG_LEN)
    return STR_OVER_MAX;
  else
    return FUNC_STATUS_OK;
}

char* BlowfishCipher::GetBuffer()
{
  return buffer.bytes;
}

func_status BlowfishCipher::Encipher()
{
  if (buffer.bytes[0] =='\0')
    return NULL_MSG;

  /* If necessary, pad the buffer up to MAX_MSG_LEN with random bytes. */
  unsigned int i=0;
  while(buffer.bytes[++i] != '\0');
  while(i++ < MAX_MSG_LEN)
  {
    buffer.bytes[i] = rand();
  }
  /* Done padding */
  
  /* ENCRYPT */
  message hbuffer;
  for(int i=0; i<MAX_MSG_LEN; ++i)
    hbuffer.bytes[i] = buffer.bytes[i];    
  
  for(int i=0; i<MAX_MSG_LEN/8; i++)
  {
    EncryptBlock(&(hbuffer.halfblocks[2*i].binary), &(hbuffer.halfblocks[2*i+1].binary));
  }
  for(int i=0; i<MAX_MSG_LEN; ++i)
    buffer.bytes[i] = hbuffer.bytes[i];
  /* DONE ENCRYPTING */
  
  return FUNC_STATUS_OK;
}

// currently in ECB mode.  This isn't very secure (relatively speaking)
func_status BlowfishCipher::Decipher()
{
  if (buffer.bytes[0] =='\0')
    return NULL_MSG;
  
  message hbuffer;
  for(int i=0; i<MAX_MSG_LEN; ++i)
    hbuffer.bytes[i] = buffer.bytes[i];    
  
  for(int i=0; i<MAX_MSG_LEN/8; ++i)
  {
    DecryptBlock(&(hbuffer.halfblocks[2*i].binary), &(hbuffer.halfblocks[2*i+1].binary));
  }
  for(int i=0; i<MAX_MSG_LEN; ++i)
    buffer.bytes[i] = hbuffer.bytes[i];

  return FUNC_STATUS_OK;
}


func_status BlowfishCipher::InitializeSubkeys(uint32* key)
{
  /* This is a seven step process as described in Schneier's "Applied Cryptography."
     The steps are given here in his words for your reference. */
     
  /* (1) Initialize first the P-array and the four S-boxes, in order, with a fixed string.
         This string consists of the hexadecimal digits of pi. */
  
     // See bfinit.h for definitions of P,S1,S2,S3,S4.
     unsigned int i=0;
     for(i = 0; i<18; ++i)
     {
       sk.P[i]  = P[i];
     }
     
     for(i = 0; i<18; ++i)         // all of these loops need to be unrolled:
     {
       sk.S[0][i] = S1[i];
     }
     
     for(i = 0; i<18; ++i)
     {
       sk.S[1][i] = S2[i];
     }
     
     for(i = 0; i<18; ++i)
     {
       sk.S[2][i] = S3[i];
     }
     
     for(i = 0; i<18; ++i)
     {
       sk.S[3][i] = S4[i];
     }                         // ^^^ all of those loops need to be unrolled ^^
     

  /* (2) XOR P[0] with the first 32 bits of the key, XOR P[1] with the second 32 bits of the key,
         and so on for all bits of the key (up to P[17]).  Repeatedly cycle through the key bits
	 until the entire P-array has been XORed with key bits. */

  sk.P[0] ^= key[0];  // bits 1-32 (Remember the key is always 448 bits in this implementation.)
  sk.P[1] ^= key[1];    // bits  -64
  sk.P[2] ^= key[2];    // bits  -96
  sk.P[3] ^= key[3];    // bits  -128
  sk.P[4] ^= key[4];    // bits  -160
  sk.P[5] ^= key[5];    // bits  -192
  sk.P[6] ^= key[6];    // bits  -224
  sk.P[7] ^= key[7];    // bits  -256
  sk.P[8] ^= key[8];    // bits  -288
  sk.P[9] ^= key[9];    // bits  -320
  sk.P[10] ^= key[11];  // bits  -352 
  sk.P[11] ^= key[12];  // bits  -384
  sk.P[12] ^= key[13];  // bits  -416
  sk.P[13] ^= key[0];   // bits 1 -32
  sk.P[14] ^= key[1];   // bits 33-64   (When you run out of key bits, wrap.)
  sk.P[15] ^= key[2];   // bits 65-96
  sk.P[16] ^= key[3];   // bits 97-128
  sk.P[17] ^= key[4];   // bits 129-160
  
  /* (3) Encrypt the all-zero string with the Blowfish algorithm, using the subkeys
         described in steps (1) and (2) above. */

  uint32 dataleft = 0x00000000, dataright = 0x00000000;
  EncryptBlock(&dataleft, &dataright);
  
  /* (4) Replace P[0] and P[1] with the output of step (3). */

  sk.P[0] = dataleft;
  sk.P[1] = dataright;
  
  /* (5) Encrypt the output of step(3) using the Blowfish algorith with the modified subkeys. */

  EncryptBlock(&dataleft, &dataright);
  
  /* (6) Replace P[2] and P[3] with the output of step (5). */

  sk.P[2] = dataleft;
  sk.P[3] = dataright;
  
  /* (7) Continue the process, replacing all elements of the P-array, and then all four S-boxes
         in order, with the output of the continuously changing Blowfish algorithm. */
  

  EncryptBlock(&dataleft, &dataright);
  sk.P[4] = dataleft;
  sk.P[5] = dataright;
  
  EncryptBlock(&dataleft, &dataright);
  sk.P[6] = dataleft;
  sk.P[7] = dataright;
  
  EncryptBlock(&dataleft, &dataright);
  sk.P[8] = dataleft;
  sk.P[9] = dataright;
  
  EncryptBlock(&dataleft, &dataright);
  sk.P[10] = dataleft;
  sk.P[11] = dataright;
  
  EncryptBlock(&dataleft, &dataright);
  sk.P[12] = dataleft;
  sk.P[13] = dataright;
  
  EncryptBlock(&dataleft, &dataright);
  sk.P[14] = dataleft;
  sk.P[15] = dataright;
  
  EncryptBlock(&dataleft, &dataright);
  sk.P[16] = dataleft;
  sk.P[17] = dataright;


  for (i=0; i<256; ++i)         // I will unroll this loop soon.. I promise.
  {
    EncryptBlock(&dataleft, &dataright);
    sk.S[0][i] = dataleft;
    sk.S[0][i] = dataright;
  }

  for (i=0; i<256; ++i)         // I will unroll this loop soon.. I promise.
  {
    EncryptBlock(&dataleft, &dataright);
    sk.S[1][i] = dataleft;
    sk.S[1][i] = dataright;
  }

  for (i=0; i<256; ++i)         // I will unroll this loop soon.. I promise.
  {
    EncryptBlock(&dataleft, &dataright);
    sk.S[2][i] = dataleft;
    sk.S[2][i] = dataright;
  }
  
  for (i=0; i<256; ++i)         // I will unroll this loop soon.. I promise.
  {
    EncryptBlock(&dataleft, &dataright);
    sk.S[3][i] = dataleft;
    sk.S[3][i] = dataright;
  }

  return FUNC_STATUS_OK;
}


func_status BlowfishCipher::EncryptBlock(uint32* left, uint32* right)
{
#ifndef XOR_SWAP_TRICK
uint32 temp = 0;
#endif
  for (int i=0; i<N; ++i)
  {
    *left = *left ^ sk.P[i];
    *right = F(*left) ^ *right;
  
    #ifdef XOR_SWAP_TRICK     // one way or another...
    *left ^= *right;                  
    *right ^= *left;                         // swap
    *left ^= *right;                 
    #endif                               // the
    #ifndef XOR_SWAP_TRICK          
    temp = *right;                  // left 
    *right = *left;              // and
    *left = temp;             // right
    #endif
  }
    
  #ifdef XOR_SWAP_TRICK    // undo the last swap
  *left ^= *right;                  
  *right ^= *left;
  *left ^= *right;
  #endif
  #ifndef XOR_SWAP_TRICK
  temp = *right;
  *right = *left;
  *left = temp;
  #endif
  
  *right = *right ^ sk.P[N];
  *left = *left ^ sk.P[N+1];

  return FUNC_STATUS_OK;
}
  
func_status BlowfishCipher::DecryptBlock(uint32* left, uint32* right)
{
#ifndef XOR_SWAP_TRICK
uint32 temp = 0;
#endif
  for (int i=N+1; i>1; --i)
  {
    *left = *left ^ sk.P[i];
    *right = F(*left) ^ *right;
  
    #ifdef XOR_SWAP_TRICK     // one way or another...
    *left ^= *right;                  
    *right ^= *left;                         // swap
    *left ^= *right;                 
    #endif                               // the
    #ifndef XOR_SWAP_TRICK          
    temp = *right;                  // left 
    *right = *left;              // and
    *left = temp;             // right
    #endif
  }
    
  #ifdef XOR_SWAP_TRICK    // undo the last swap
  *left ^= *right;                  
  *right ^= *left;
  *left ^= *right;
  #endif
  #ifndef XOR_SWAP_TRICK
  temp = *right;
  *right = *left;
  *left = temp;
  #endif
  
  *right = *right ^ sk.P[1];
  *left = *left ^ sk.P[0];

  return FUNC_STATUS_OK;
}


uint32 BlowfishCipher::F (uint32 data)
{
  /* Divide data into four 8bit quarters named a,b,c,d */
  uint8 a = data & 0xFF;
  data = data >> 8;
  
  uint8 b = data & 0xFF;
  data = data >> 8;
  
  uint8 c = data & 0xFF;
  data = data >> 8;
  
  uint8 d = data & 0xFF;

  return (((sk.S[0][a] + sk.S[1][b]) ^ sk.S[2][c]) + sk.S[3][d]);
}

