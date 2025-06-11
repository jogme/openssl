/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <assert.h>
#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include "internal/namemap.h"
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/cmac.h>
#ifndef FIPS_MODULE
# include <openssl/engine.h>
#endif
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/encoder.h>
#include <openssl/core_names.h>

#include "internal/numbers.h"   /* includes SIZE_MAX */
#include "internal/ffc.h"
#include "crypto/evp.h"
#include "crypto/dh.h"
#include "crypto/dsa.h"
#include "crypto/ec.h"
#include "crypto/ecx.h"
#include "crypto/rsa.h"
#ifndef FIPS_MODULE
# include "crypto/asn1.h"
# include "crypto/x509.h"
#endif
#include "internal/provider.h"
#include "evp_local.h"

# ifndef OPENSSL_NO_DSA
static DSA *evp_pkey_get0_DSA_int(const EVP_PKEY *pkey)
{
    if (pkey->type != EVP_PKEY_DSA) {
        ERR_raise(ERR_LIB_EVP, EVP_R_EXPECTING_A_DSA_KEY);
        return NULL;
    }
    return evp_pkey_get_legacy((EVP_PKEY *)pkey);
}

const DSA *EVP_PKEY_get0_DSA(const EVP_PKEY *pkey)
{
    return evp_pkey_get0_DSA_int(pkey);
}

int EVP_PKEY_set1_DSA(EVP_PKEY *pkey, DSA *key)
{
    int ret;

    if (!DSA_up_ref(key))
        return 0;

    ret = EVP_PKEY_assign_DSA(pkey, key);

    if (!ret)
        DSA_free(key);

    return ret;
}
DSA *EVP_PKEY_get1_DSA(EVP_PKEY *pkey)
{
    DSA *ret = evp_pkey_get0_DSA_int(pkey);

    if (ret != NULL && !DSA_up_ref(ret))
        return NULL;

    return ret;
}
# endif /*  OPENSSL_NO_DSA */

# ifndef OPENSSL_NO_ECX
static const ECX_KEY *evp_pkey_get0_ECX_KEY(const EVP_PKEY *pkey, int type)
{
    if (EVP_PKEY_get_base_id(pkey) != type) {
        ERR_raise(ERR_LIB_EVP, EVP_R_EXPECTING_A_ECX_KEY);
        return NULL;
    }
    return evp_pkey_get_legacy((EVP_PKEY *)pkey);
}

static ECX_KEY *evp_pkey_get1_ECX_KEY(EVP_PKEY *pkey, int type)
{
    ECX_KEY *ret = (ECX_KEY *)evp_pkey_get0_ECX_KEY(pkey, type);

    if (ret != NULL && !ossl_ecx_key_up_ref(ret))
        ret = NULL;
    return ret;
}

#  define IMPLEMENT_ECX_VARIANT(NAME)                                   \
    ECX_KEY *ossl_evp_pkey_get1_##NAME(EVP_PKEY *pkey)                  \
    {                                                                   \
        return evp_pkey_get1_ECX_KEY(pkey, EVP_PKEY_##NAME);            \
    }
IMPLEMENT_ECX_VARIANT(X25519)
IMPLEMENT_ECX_VARIANT(X448)
IMPLEMENT_ECX_VARIANT(ED25519)
IMPLEMENT_ECX_VARIANT(ED448)

# endif /* OPENSSL_NO_ECX */

# if !defined(OPENSSL_NO_DH) && !defined(OPENSSL_NO_DEPRECATED_3_0)

int EVP_PKEY_set1_DH(EVP_PKEY *pkey, DH *dhkey)
{
    int ret, type;

    /*
     * ossl_dh_is_named_safe_prime_group() returns 1 for named safe prime groups
     * related to ffdhe and modp (which cache q = (p - 1) / 2),
     * and returns 0 for all other dh parameter generation types including
     * RFC5114 named groups.
     *
     * The EVP_PKEY_DH type is used for dh parameter generation types:
     *  - named safe prime groups related to ffdhe and modp
     *  - safe prime generator
     *
     * The type EVP_PKEY_DHX is used for dh parameter generation types
     *  - fips186-4 and fips186-2
     *  - rfc5114 named groups.
     *
     * The EVP_PKEY_DH type is used to save PKCS#3 data than can be stored
     * without a q value.
     * The EVP_PKEY_DHX type is used to save X9.42 data that requires the
     * q value to be stored.
     */
    if (ossl_dh_is_named_safe_prime_group(dhkey))
        type = EVP_PKEY_DH;
    else
        type = DH_get0_q(dhkey) == NULL ? EVP_PKEY_DH : EVP_PKEY_DHX;

    if (!DH_up_ref(dhkey))
        return 0;

    ret = EVP_PKEY_assign(pkey, type, dhkey);

    if (!ret)
        DH_free(dhkey);

    return ret;
}

DH *evp_pkey_get0_DH_int(const EVP_PKEY *pkey)
{
    if (pkey->type != EVP_PKEY_DH && pkey->type != EVP_PKEY_DHX) {
        ERR_raise(ERR_LIB_EVP, EVP_R_EXPECTING_A_DH_KEY);
        return NULL;
    }
    return evp_pkey_get_legacy((EVP_PKEY *)pkey);
}

const DH *EVP_PKEY_get0_DH(const EVP_PKEY *pkey)
{
    return evp_pkey_get0_DH_int(pkey);
}

DH *EVP_PKEY_get1_DH(EVP_PKEY *pkey)
{
    DH *ret = evp_pkey_get0_DH_int(pkey);

    if (ret != NULL && !DH_up_ref(ret))
        ret = NULL;

    return ret;
}
# endif

int EVP_PKEY_can_sign(const EVP_PKEY *pkey)
{
    if (pkey->keymgmt == NULL) {
        switch (EVP_PKEY_get_base_id(pkey)) {
        case EVP_PKEY_RSA:
        case EVP_PKEY_RSA_PSS:
            return 1;
# ifndef OPENSSL_NO_DSA
        case EVP_PKEY_DSA:
            return 1;
# endif
# ifndef OPENSSL_NO_EC
        case EVP_PKEY_ED25519:
        case EVP_PKEY_ED448:
            return 1;
        case EVP_PKEY_EC:        /* Including SM2 */
            return EC_KEY_can_sign(pkey->pkey.ec);
# endif
        default:
            break;
        }
    } else {
        const OSSL_PROVIDER *prov = EVP_KEYMGMT_get0_provider(pkey->keymgmt);
        OSSL_LIB_CTX *libctx = ossl_provider_libctx(prov);
        const char *supported_sig =
            pkey->keymgmt->query_operation_name != NULL
            ? pkey->keymgmt->query_operation_name(OSSL_OP_SIGNATURE)
            : EVP_KEYMGMT_get0_name(pkey->keymgmt);
        EVP_SIGNATURE *signature = NULL;

        signature = EVP_SIGNATURE_fetch(libctx, supported_sig, NULL);
        if (signature != NULL) {
            EVP_SIGNATURE_free(signature);
            return 1;
        }
    }
    return 0;
}

#ifndef FIPS_MODULE
int EVP_PKEY_get_ec_point_conv_form(const EVP_PKEY *pkey)
{
    char name[80];
    size_t name_len;

    if (pkey == NULL)
        return 0;

    if (pkey->keymgmt == NULL
            || pkey->keydata == NULL) {
# ifndef OPENSSL_NO_EC
        /* Might work through the legacy route */
        const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);

        if (ec == NULL)
            return 0;

        return EC_KEY_get_conv_form(ec);
# else
        return 0;
# endif
    }

    if (!EVP_PKEY_get_utf8_string_param(pkey,
                                        OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                        name, sizeof(name), &name_len))
        return 0;

    if (strcmp(name, "uncompressed") == 0)
        return POINT_CONVERSION_UNCOMPRESSED;

    if (strcmp(name, "compressed") == 0)
        return POINT_CONVERSION_COMPRESSED;

    if (strcmp(name, "hybrid") == 0)
        return POINT_CONVERSION_HYBRID;

    return 0;
}

int EVP_PKEY_get_field_type(const EVP_PKEY *pkey)
{
    char fstr[80];
    size_t fstrlen;

    if (pkey == NULL)
        return 0;

    if (pkey->keymgmt == NULL
            || pkey->keydata == NULL) {
# ifndef OPENSSL_NO_EC
        /* Might work through the legacy route */
        const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
        const EC_GROUP *grp;

        if (ec == NULL)
            return 0;
        grp = EC_KEY_get0_group(ec);
        if (grp == NULL)
            return 0;

        return EC_GROUP_get_field_type(grp);
# else
        return 0;
# endif
    }

    if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_EC_FIELD_TYPE,
                                        fstr, sizeof(fstr), &fstrlen))
        return 0;

    if (strcmp(fstr, SN_X9_62_prime_field) == 0)
        return NID_X9_62_prime_field;
    else if (strcmp(fstr, SN_X9_62_characteristic_two_field))
        return NID_X9_62_characteristic_two_field;

    return 0;
}
#endif

static void detect_foreign_key(EVP_PKEY *pkey)
{
    switch (pkey->type) {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA_PSS:
        pkey->foreign = pkey->pkey.rsa != NULL
                        && ossl_rsa_is_foreign(pkey->pkey.rsa);
        break;
#  ifndef OPENSSL_NO_EC
    case EVP_PKEY_SM2:
        break;
    case EVP_PKEY_EC:
        pkey->foreign = pkey->pkey.ec != NULL
                        && ossl_ec_key_is_foreign(pkey->pkey.ec);
        break;
#  endif
#  ifndef OPENSSL_NO_DSA
    case EVP_PKEY_DSA:
        pkey->foreign = pkey->pkey.dsa != NULL
                        && ossl_dsa_is_foreign(pkey->pkey.dsa);
        break;
#endif
#  ifndef OPENSSL_NO_DH
    case EVP_PKEY_DH:
        pkey->foreign = pkey->pkey.dh != NULL
                        && ossl_dh_is_foreign(pkey->pkey.dh);
        break;
#endif
    default:
        pkey->foreign = 0;
        break;
    }
}

int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key)
{
#  ifndef OPENSSL_NO_EC
    int pktype;

    pktype = EVP_PKEY_type(type);
    if ((key != NULL) && (pktype == EVP_PKEY_EC || pktype == EVP_PKEY_SM2)) {
        const EC_GROUP *group = EC_KEY_get0_group(key);

        if (group != NULL) {
            int curve = EC_GROUP_get_curve_name(group);

            /*
             * Regardless of what is requested the SM2 curve must be SM2 type,
             * and non SM2 curves are EC type.
             */
            if (curve == NID_sm2 && pktype == EVP_PKEY_EC)
                type = EVP_PKEY_SM2;
            else if(curve != NID_sm2 && pktype == EVP_PKEY_SM2)
                type = EVP_PKEY_EC;
        }
    }
#  endif

    if (pkey == NULL || !EVP_PKEY_set_type(pkey, type))
        return 0;

    pkey->pkey.ptr = key;
    detect_foreign_key(pkey);

    return (key != NULL);
}
