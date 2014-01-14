
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>

#include "bfinit.h"
#include "blowfish.cpp"

int main(int argc, char *argv[])
{
  BlowfishCipher cipher;
  
  cipher.SetBuffer("Design and programming are human activities; forget that and all is lost. - Bjarne Stroustrup");
  
  cout << cipher.GetBuffer() << endl;
  cipher.Encipher();
  cout << cipher.GetBuffer() << endl;
  cipher.Decipher();
  cout << cipher.GetBuffer() << endl;
   
  return FUNC_STATUS_OK;
}
