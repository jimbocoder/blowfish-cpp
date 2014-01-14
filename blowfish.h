#ifndef BLOWFISH_H
#define BLOWFISH_H

#include "bfinit.h"
	
class BlowfishCipher {
  public:
    //members:
    
    //default functions:
    BlowfishCipher();
    ~BlowfishCipher();
    //helper functions:
    uint32*     GetKey();
    func_status SetKey(uint32 key[14]);
    func_status SetBuffer(char* buf);
    func_status SetBuffer(std::string str);
    char*       GetBuffer();
    func_status Encipher();
    func_status Decipher();
    
    
    
  private:
    // members:
    uint32 key[14];  // 448bit key
    message buffer;
    subkeys sk;
    //functions:
    func_status InitializeSubkeys (uint32* key);
    func_status EncryptBlock (uint32 *left, uint32 *right);  
    func_status DecryptBlock (uint32 *left, uint32 *right);
    uint32 F (uint32 x);  
    

};

#endif
