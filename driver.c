#include <stdio.h>
#include <stdlib.h>
#include "crc16.h"

int main(int arg, char* argc[])
{

   //pulse const sums up to 0
   //const uint8_t  buf[] = { 0x5c, 0x00, 0x01, 0x00, 0xd0, 0x07, 0x01, 0x00, 
   //                         0x60, 0x00, 0x64, 0x00, 0x8c, 0x00, 0x01, 0x00,
   //                         0x1f, 0x00, 0xfa, 0x00, 0x01, 0x00, 0x90, 0xfd}; 

  // program def sums to 0
  const uint8_t buf[] = {

      0x01,0x00,0x45,0x5f,0x53,0x5f,0x43,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x03,0xf1,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x50,0x75,0x6c,0x73,0x65,0x41,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x50,0x00,0x32,0x00,0x11,0x00,0x0a,0x00,0xc8,0x00,
      //    changed this byte---+
      //    from 0x64 to 0x63   |
      //                        V
      0xf4,0x01,0x5e,0x01,0x9c,0x63,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // <=changed the 0x64 to 0x63
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x00,
      0x00,0x00,0x00,0x00,0x50,0x75,0x6c,0x73,0x65,0x42,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x00,0x00,0x00,
      0x00,0x00,0x50,0x75,0x6c,0x73,0x65,0x43,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x00,0x00,
      0x50,0x75,0x6c,0x73,0x65,0x44,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x8c,0x9f // original crc is 0x6b 0x6f 

   };


   int buf_len = sizeof(buf);

   for(int i=0; i<buf_len; i++)
       printf("%d: 0x%02x\n", i, buf[i]);

   printf("CRC is 0x%x\n", crc16(buf, buf_len));

   return 0;
}
