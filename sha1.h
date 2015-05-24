/* public api for steve reid's public domain SHA-1 implementation */
/* this file is in the public domain */

/** @file
 *  SHA-1 hash API.
 */

#ifndef __SHA1_H
#define __SHA1_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned int  state[5];
    unsigned int  count[2];
    unsigned char buffer[64];
} SHA1_CTX;

#define SHA1_DIGEST_LENGTH 20

void SHA1_Init(SHA1_CTX* context);
void SHA1_Update(SHA1_CTX* context, const void* data, unsigned long len);
void SHA1_Final(unsigned char* digest, SHA1_CTX* context);

#ifdef __cplusplus
}
#endif

#endif /* __SHA1_H */
