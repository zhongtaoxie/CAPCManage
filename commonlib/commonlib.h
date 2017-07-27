/* -------------------------------------------------------------------------
*      Copyright (c) 2007     JianShen.
*                             All rights reserved.
*   This source code and any compilation or derivative thereof is the
*   proprietary information of Author(s). and is confidential in nature.
*
*   Under no circumstances is this software to be combined with any Open
*   Source Software in any way or placed under an Open Source License of
*   any type without the express written permission of  Author(s).
* ------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 *  Description:  
 *   	header for comm libarary.
 *  Author: Jian Shen
 *  Created:2007/08/09
 *  Change History:
 * ------------------------------------------------------------------------- */
#ifndef _COMMONLIB_H_
#define _COMMONLIB_H_

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>


#define THREAD_CREATE(tid, entry, arg) do { _beginthread((entry), 0,(arg));\
(tid) =GetCurrentThreadId(); \
 } while (0)

#define PORT "11111"
#define SERVER "localhost"//"server.jian.com"
#define CLIENT "localhost"//"client.jian.com"

#define DATA_DIR  "..\\openssl\\data"

#define int_error(errmsg) handle_error(__FILE__, __LINE__, errmsg)
void handle_error(const char *file, int lineno, const char *errmsg);

void init_OpenSSL(void);

//define mutex for multithread supporting.
//#define MUTEX_CREATE(x) (x) = CreateMutex(NULL, FALSE, NULL)
//#define MUTEX_CLEANUP(x) CloseHandle(x)
#define MUTEX_LOCK(x) WaitForSingleObject((x), INFINITE)
#define MUTEX_UNLOCK(x) ReleaseMutex(x)
#define THREAD_ID GetCurrentThreadId()

int thread_setup(void);
int thread_cleanup(void);

//seeding
void seed_prng();

//callback for certificate verify
int verify_callback(int ok, X509_STORE_CTX *store);

//check the fields in certification after the connection is ready
long post_connection_check(SSL *ssl, char *host);

//get digest algorithm according to the key type
//it will used to select the digest alogrithm when signing a certificate
const EVP_MD* getDigestByPkeyType(int pkey_type);

typedef struct _keyvaluepair
{
    char *key;
    char *value;
} st_keyvalue;


#endif