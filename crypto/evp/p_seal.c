/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/provider.h"
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

int OPENSSL_BOX_EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                 unsigned char **ek, int *ekl, unsigned char *iv,
                 EVP_PKEY **pubk, int npubk)
{
    unsigned char key[EVP_MAX_KEY_LENGTH];
    const OSSL_PROVIDER *prov;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_CIPHER *cipher;
    int i, len;
    int rv = 0;

    if (type != NULL) {
        OPENSSL_BOX_EVP_CIPHER_CTX_reset(ctx);
        if (!OPENSSL_BOX_EVP_EncryptInit_ex(ctx, type, NULL, NULL, NULL))
            return 0;
    }
    if ((cipher = OPENSSL_BOX_EVP_CIPHER_CTX_get0_cipher(ctx)) != NULL
            && (prov = OPENSSL_BOX_EVP_CIPHER_get0_provider(cipher)) != NULL)
        libctx = ossl_provider_libctx(prov);
    if ((npubk <= 0) || !pubk)
        return 1;

    if (OPENSSL_BOX_EVP_CIPHER_CTX_rand_key(ctx, key) <= 0)
        return 0;

    len = OPENSSL_BOX_EVP_CIPHER_CTX_get_iv_length(ctx);
    if (len < 0 || RAND_priv_bytes_ex(libctx, iv, len, 0) <= 0)
        goto err;

    len = OPENSSL_BOX_EVP_CIPHER_CTX_get_key_length(ctx);
    if (len < 0)
        goto err;

    if (!OPENSSL_BOX_EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        goto err;

    for (i = 0; i < npubk; i++) {
        size_t keylen = len;

        pctx = OPENSSL_BOX_EVP_PKEY_CTX_new_from_pkey(libctx, pubk[i], NULL);
        if (pctx == NULL) {
            ERR_raise(ERR_LIB_EVP, ERR_R_EVP_LIB);
            goto err;
        }

        if (OPENSSL_BOX_EVP_PKEY_encrypt_init(pctx) <= 0
            || OPENSSL_BOX_EVP_PKEY_encrypt(pctx, ek[i], &keylen, key, keylen) <= 0)
            goto err;
        ekl[i] = (int)keylen;
        OPENSSL_BOX_EVP_PKEY_CTX_free(pctx);
    }
    pctx = NULL;
    rv = npubk;
err:
    OPENSSL_BOX_EVP_PKEY_CTX_free(pctx);
    OPENSSL_cleanse(key, sizeof(key));
    return rv;
}

int OPENSSL_BOX_EVP_SealFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int i;
    i = OPENSSL_BOX_EVP_EncryptFinal_ex(ctx, out, outl);
    if (i)
        i = OPENSSL_BOX_EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL);
    return i;
}
