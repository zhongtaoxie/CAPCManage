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
 *   	implementation for comm libarary.
 *  Author: Jian Shen
 *  Created:2007/08/09
 *  Change History:
 * ------------------------------------------------------------------------- */
#include "stdafx.h"
#include "commonlib.h"
#include "time.h"

static HANDLE *lock_h;
//callback for the locking.
void win32_locking_callback(int mode,int type,const char *file,int line);
//callback for id function
unsigned long id_function(void);


int thread_setup(void)
{
    int i;

    lock_h=(HANDLE *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(HANDLE));
    if( NULL==lock_h )
    {
        return 0;
    }

    for (i=0; i<CRYPTO_num_locks(); i++)
    {
        lock_h[i]=CreateMutex(NULL,FALSE,NULL);
    }

    CRYPTO_set_locking_callback( win32_locking_callback );
    CRYPTO_set_id_callback( id_function );
    
    return 1;
}

int thread_cleanup(void)
{
    int i;
    if( NULL==lock_h )
    {
        return 0;
    }

    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
    for (i=0; i<CRYPTO_num_locks(); i++)
        CloseHandle(lock_h[i]);
    OPENSSL_free(lock_h);
    lock_h=NULL;
    return 1;
}

void win32_locking_callback(int mode, int n, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        MUTEX_LOCK(lock_h[n]);
    else
        MUTEX_UNLOCK(lock_h[n]);
}

static unsigned long id_function(void)
{
    return ((unsigned long)THREAD_ID);
}

void handle_error(const char *file, int lineno, const char *errmsg)
{
    fprintf(stderr, "** %s:%i %s\n", file, lineno, errmsg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

void init_OpenSSL(void)
{
    if (!thread_setup() || ! SSL_library_init())
    {
        fprintf(stderr, "** OpenSSL initialization failed!\n");
        exit(-1);
    }
    SSL_load_error_strings();
}

//seeding
void seed_prng()
{
      time_t rawtime;
      struct tm* timeinfo;

      time(&rawtime);
      timeinfo = localtime(&rawtime);
      RAND_seed(asctime(timeinfo), 4);
}

//callback for certificate verify
int verify_callback(int ok, X509_STORE_CTX *store)
{
    char data[256];
    if (!ok)
    {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int depth = X509_STORE_CTX_get_error_depth(store);
        int err = X509_STORE_CTX_get_error(store);
        fprintf(stderr, "-Error with certificate at depth: %i\n",depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        fprintf(stderr, " issuer = %s\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        fprintf(stderr, " subject = %s\n", data);
        fprintf(stderr, " err %i:%s\n", err,
                X509_verify_cert_error_string(err));
    }
    return ok;
}

//check the fields in certification after the connection is ready
long post_connection_check(SSL *ssl, char *host)
{
    X509 *cert;
    X509_NAME *subj;
    int extcount;
    int ok = 0;
    /* Checking the return from SSL_get_peer_certificate here is not
    * strictly necessary. With our example programs, it is not
    * possible for it to return NULL. However, it is good form to
    * check the return since it can return NULL if the examples are
    * modified to enable anonymous ciphers or for the server to not
    * require a client certificate.
    */
    /* return an error in case of following symptoms:
    1.If no peer certificate is found
    2.If it is called with a NULL second argument, i.e., if no FQDN is specified to compare
against
    3. If the dNSName fields found (if any) do not match the host argument and the
commonName also doesn't match the host argument (if found)
    4.Any time the SSL_get_verify_result routine returns an error
   */
    if (!(cert = SSL_get_peer_certificate(ssl)) || !host)
        goto err;
    if ((extcount = X509_get_ext_count(cert)) > 0)
    {
        int i;
        for (i = 0; i < extcount; i++)
        {            
            X509_EXTENSION *ext;
            const char *extstr=NULL;
            ext=X509_get_ext(cert, i);
            extstr=OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
            if (!strcmp(extstr, "subjectAltName"))
            {
                int j;
                unsigned char *data;
                STACK_OF(CONF_VALUE) *val;
                CONF_VALUE *nval;
                X509V3_EXT_METHOD *meth;
                if (!(meth = X509V3_EXT_get(ext)))
                    break;
                data = ext->value->data;
                val = meth->i2v(meth,
                    meth->d2i(NULL, (const unsigned char**)&data, ext->value->length),NULL);
                for (j = 0; j < sk_CONF_VALUE_num(val); j++)
                {
                    nval = sk_CONF_VALUE_value(val, j);
                    if (!strcmp(nval->name, "DNS") 
                        && !strcmp(nval->value, host))
                    {
                        ok = 1;
                        break;
                    }
                }
            }
            if (ok)
                break;
        }
    }

    char subj_data[256];
    if (!ok && (subj = X509_get_subject_name(cert)) &&
        X509_NAME_get_text_by_NID(subj,NID_commonName,subj_data,256)>0)
    {
        subj_data[255] = 0;
        if (stricmp(subj_data, host) != 0)
            goto err;
    }
    X509_free(cert);
    return SSL_get_verify_result(ssl);
err:
    if (cert)
    {
        X509_free(cert);
    }
    return X509_V_ERR_APPLICATION_VERIFICATION;
}

const EVP_MD* getDigestByPkeyType(int pkey_type)
{
    const EVP_MD* digest=NULL;
    if (EVP_PKEY_type(pkey_type) == EVP_PKEY_DSA)
    {
        digest = EVP_dss1();
    }
    else if (EVP_PKEY_type(pkey_type) == EVP_PKEY_RSA)
    {
        digest = EVP_sha1();
    }
    return digest;
}