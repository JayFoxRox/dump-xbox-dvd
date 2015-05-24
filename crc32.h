/* this file is in the public domain */

#ifndef _CRC32_H
#define _CRC32_H

typedef struct {
  unsigned int crc;
} CRC32_CTX;

void CRC32_Init(CRC32_CTX *context);
void CRC32_Update(CRC32_CTX *context, const void *data, unsigned long len);
void CRC32_Final(unsigned int *crc, CRC32_CTX *context);

#endif /* _CRC32_H */
