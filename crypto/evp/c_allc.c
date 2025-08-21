/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include "crypto/evp.h"
#include <openssl/pkcs12.h>
#include <openssl/objects.h>

void openssl_add_all_ciphers_int(void)
{

#ifndef OPENSSL_NO_DES
    OPENSSL_BOX_EVP_add_cipher(EVP_des_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_des_cfb1());
    OPENSSL_BOX_EVP_add_cipher(EVP_des_cfb8());
    OPENSSL_BOX_EVP_add_cipher(EVP_des_ede_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_des_ede3_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_des_ede3_cfb1());
    OPENSSL_BOX_EVP_add_cipher(EVP_des_ede3_cfb8());

    OPENSSL_BOX_EVP_add_cipher(EVP_des_ofb());
    OPENSSL_BOX_EVP_add_cipher(EVP_des_ede_ofb());
    OPENSSL_BOX_EVP_add_cipher(EVP_des_ede3_ofb());

    OPENSSL_BOX_EVP_add_cipher(EVP_desx_cbc());
    EVP_add_cipher_alias(SN_desx_cbc, "DESX");
    EVP_add_cipher_alias(SN_desx_cbc, "desx");

    OPENSSL_BOX_EVP_add_cipher(EVP_des_cbc());
    EVP_add_cipher_alias(SN_des_cbc, "DES");
    EVP_add_cipher_alias(SN_des_cbc, "des");
    OPENSSL_BOX_EVP_add_cipher(EVP_des_ede_cbc());
    OPENSSL_BOX_EVP_add_cipher(EVP_des_ede3_cbc());
    EVP_add_cipher_alias(SN_des_ede3_cbc, "DES3");
    EVP_add_cipher_alias(SN_des_ede3_cbc, "des3");

    OPENSSL_BOX_EVP_add_cipher(EVP_des_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_des_ede());
    EVP_add_cipher_alias(SN_des_ede_ecb, "DES-EDE-ECB");
    EVP_add_cipher_alias(SN_des_ede_ecb, "des-ede-ecb");
    OPENSSL_BOX_EVP_add_cipher(EVP_des_ede3());
    EVP_add_cipher_alias(SN_des_ede3_ecb, "DES-EDE3-ECB");
    EVP_add_cipher_alias(SN_des_ede3_ecb, "des-ede3-ecb");
    OPENSSL_BOX_EVP_add_cipher(EVP_des_ede3_wrap());
    EVP_add_cipher_alias(SN_id_smime_alg_CMS3DESwrap, "des3-wrap");
#endif

#ifndef OPENSSL_NO_RC4
    OPENSSL_BOX_EVP_add_cipher(OPENSSL_BOX_EVP_rc4());
    OPENSSL_BOX_EVP_add_cipher(EVP_rc4_40());
# ifndef OPENSSL_NO_MD5
    OPENSSL_BOX_EVP_add_cipher(EVP_rc4_hmac_md5());
# endif
#endif

#ifndef OPENSSL_NO_IDEA
    OPENSSL_BOX_EVP_add_cipher(EVP_idea_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_idea_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_idea_ofb());
    OPENSSL_BOX_EVP_add_cipher(EVP_idea_cbc());
    EVP_add_cipher_alias(SN_idea_cbc, "IDEA");
    EVP_add_cipher_alias(SN_idea_cbc, "idea");
#endif

#ifndef OPENSSL_NO_SEED
    OPENSSL_BOX_EVP_add_cipher(EVP_seed_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_seed_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_seed_ofb());
    OPENSSL_BOX_EVP_add_cipher(EVP_seed_cbc());
    EVP_add_cipher_alias(SN_seed_cbc, "SEED");
    EVP_add_cipher_alias(SN_seed_cbc, "seed");
#endif

#ifndef OPENSSL_NO_SM4
    OPENSSL_BOX_EVP_add_cipher(EVP_sm4_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_sm4_cbc());
    OPENSSL_BOX_EVP_add_cipher(EVP_sm4_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_sm4_ofb());
    OPENSSL_BOX_EVP_add_cipher(EVP_sm4_ctr());
    EVP_add_cipher_alias(SN_sm4_cbc, "SM4");
    EVP_add_cipher_alias(SN_sm4_cbc, "sm4");
#endif

#ifndef OPENSSL_NO_RC2
    OPENSSL_BOX_EVP_add_cipher(EVP_rc2_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_rc2_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_rc2_ofb());
    OPENSSL_BOX_EVP_add_cipher(EVP_rc2_cbc());
    OPENSSL_BOX_EVP_add_cipher(EVP_rc2_40_cbc());
    OPENSSL_BOX_EVP_add_cipher(EVP_rc2_64_cbc());
    EVP_add_cipher_alias(SN_rc2_cbc, "RC2");
    EVP_add_cipher_alias(SN_rc2_cbc, "rc2");
    EVP_add_cipher_alias(SN_rc2_cbc, "rc2-128");
    EVP_add_cipher_alias(SN_rc2_64_cbc, "rc2-64");
    EVP_add_cipher_alias(SN_rc2_40_cbc, "rc2-40");
#endif

#ifndef OPENSSL_NO_BF
    OPENSSL_BOX_EVP_add_cipher(EVP_bf_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_bf_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_bf_ofb());
    OPENSSL_BOX_EVP_add_cipher(EVP_bf_cbc());
    EVP_add_cipher_alias(SN_bf_cbc, "BF");
    EVP_add_cipher_alias(SN_bf_cbc, "bf");
    EVP_add_cipher_alias(SN_bf_cbc, "blowfish");
#endif

#ifndef OPENSSL_NO_CAST
    OPENSSL_BOX_EVP_add_cipher(EVP_cast5_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_cast5_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_cast5_ofb());
    OPENSSL_BOX_EVP_add_cipher(EVP_cast5_cbc());
    EVP_add_cipher_alias(SN_cast5_cbc, "CAST");
    EVP_add_cipher_alias(SN_cast5_cbc, "cast");
    EVP_add_cipher_alias(SN_cast5_cbc, "CAST-cbc");
    EVP_add_cipher_alias(SN_cast5_cbc, "cast-cbc");
#endif

#ifndef OPENSSL_NO_RC5
    OPENSSL_BOX_EVP_add_cipher(EVP_rc5_32_12_16_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_rc5_32_12_16_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_rc5_32_12_16_ofb());
    OPENSSL_BOX_EVP_add_cipher(EVP_rc5_32_12_16_cbc());
    EVP_add_cipher_alias(SN_rc5_cbc, "rc5");
    EVP_add_cipher_alias(SN_rc5_cbc, "RC5");
#endif

    OPENSSL_BOX_EVP_add_cipher(EVP_aes_128_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_128_cbc());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_128_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_128_cfb1());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_128_cfb8());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_128_ofb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_128_ctr());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_128_gcm());
#ifndef OPENSSL_NO_OCB
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_128_ocb());
#endif
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_128_xts());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_128_ccm());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_128_wrap());
    EVP_add_cipher_alias(SN_id_aes128_wrap, "aes128-wrap");
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_128_wrap_pad());
    EVP_add_cipher_alias(SN_id_aes128_wrap_pad, "aes128-wrap-pad");
    EVP_add_cipher_alias(SN_aes_128_cbc, "AES128");
    EVP_add_cipher_alias(SN_aes_128_cbc, "aes128");
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_192_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_192_cbc());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_192_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_192_cfb1());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_192_cfb8());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_192_ofb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_192_ctr());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_192_gcm());
#ifndef OPENSSL_NO_OCB
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_192_ocb());
#endif
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_192_ccm());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_192_wrap());
    EVP_add_cipher_alias(SN_id_aes192_wrap, "aes192-wrap");
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_192_wrap_pad());
    EVP_add_cipher_alias(SN_id_aes192_wrap_pad, "aes192-wrap-pad");
    EVP_add_cipher_alias(SN_aes_192_cbc, "AES192");
    EVP_add_cipher_alias(SN_aes_192_cbc, "aes192");
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_256_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_256_cbc());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_256_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_256_cfb1());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_256_cfb8());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_256_ofb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_256_ctr());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_256_gcm());
#ifndef OPENSSL_NO_OCB
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_256_ocb());
#endif
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_256_xts());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_256_ccm());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_256_wrap());
    EVP_add_cipher_alias(SN_id_aes256_wrap, "aes256-wrap");
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_256_wrap_pad());
    EVP_add_cipher_alias(SN_id_aes256_wrap_pad, "aes256-wrap-pad");
    EVP_add_cipher_alias(SN_aes_256_cbc, "AES256");
    EVP_add_cipher_alias(SN_aes_256_cbc, "aes256");
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_128_cbc_hmac_sha1());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_256_cbc_hmac_sha1());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_128_cbc_hmac_sha256());
    OPENSSL_BOX_EVP_add_cipher(EVP_aes_256_cbc_hmac_sha256());
#ifndef OPENSSL_NO_ARIA
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_128_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_128_cbc());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_128_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_128_cfb1());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_128_cfb8());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_128_ctr());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_128_ofb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_128_gcm());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_128_ccm());
    EVP_add_cipher_alias(SN_aria_128_cbc, "ARIA128");
    EVP_add_cipher_alias(SN_aria_128_cbc, "aria128");
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_192_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_192_cbc());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_192_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_192_cfb1());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_192_cfb8());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_192_ctr());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_192_ofb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_192_gcm());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_192_ccm());
    EVP_add_cipher_alias(SN_aria_192_cbc, "ARIA192");
    EVP_add_cipher_alias(SN_aria_192_cbc, "aria192");
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_256_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_256_cbc());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_256_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_256_cfb1());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_256_cfb8());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_256_ctr());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_256_ofb());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_256_gcm());
    OPENSSL_BOX_EVP_add_cipher(EVP_aria_256_ccm());
    EVP_add_cipher_alias(SN_aria_256_cbc, "ARIA256");
    EVP_add_cipher_alias(SN_aria_256_cbc, "aria256");
#endif

#ifndef OPENSSL_NO_CAMELLIA
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_128_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_128_cbc());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_128_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_128_cfb1());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_128_cfb8());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_128_ofb());
    EVP_add_cipher_alias(SN_camellia_128_cbc, "CAMELLIA128");
    EVP_add_cipher_alias(SN_camellia_128_cbc, "camellia128");
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_192_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_192_cbc());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_192_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_192_cfb1());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_192_cfb8());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_192_ofb());
    EVP_add_cipher_alias(SN_camellia_192_cbc, "CAMELLIA192");
    EVP_add_cipher_alias(SN_camellia_192_cbc, "camellia192");
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_256_ecb());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_256_cbc());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_256_cfb());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_256_cfb1());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_256_cfb8());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_256_ofb());
    EVP_add_cipher_alias(SN_camellia_256_cbc, "CAMELLIA256");
    EVP_add_cipher_alias(SN_camellia_256_cbc, "camellia256");
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_128_ctr());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_192_ctr());
    OPENSSL_BOX_EVP_add_cipher(EVP_camellia_256_ctr());
#endif

#ifndef OPENSSL_NO_CHACHA
    OPENSSL_BOX_EVP_add_cipher(EVP_chacha20());
# ifndef OPENSSL_NO_POLY1305
    OPENSSL_BOX_EVP_add_cipher(EVP_chacha20_poly1305());
# endif
#endif
}
