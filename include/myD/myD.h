/*
 * Copyright 2012 Mo McRoberts.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef MYD_H_
# define MYD_H_                         1

# include <stdarg.h>

# include <openssl/rsa.h>
# include <openssl/dsa.h>
# include <openssl/dh.h>
# include <openssl/ec.h>
# include <openssl/evp.h>
# include <openssl/x509.h>
# include <openssl/bio.h>

# include <redland.h>

typedef struct myd_s myd;
typedef struct myd_policy_s myd_policy;
typedef struct myd_cert_s myd_cert;
typedef struct myd_key_s myd_key;

typedef int (*myd_debug_handler)(const myd_policy *policy, int level, const char *fmt, va_list ap);

typedef enum
{
	MYD_CT_UNKNOWN = 0,
	MYD_CT_X509,
	MYD_CT_PGP		
} myd_certtype;

typedef enum
{
	MYD_KT_UNKNOWN = 0,
	MYD_KT_RSA = EVP_PKEY_RSA, /* 6 */
	MYD_KT_DSA = EVP_PKEY_DSA, /* 116 */
	MYD_KT_DH = EVP_PKEY_DH, /* 28 */
	MYD_KT_EC = EVP_PKEY_EC, /* 408 */
	MYD_KT_ELGAMAL = -1
} myd_keytype;

typedef enum
{
	MYD_URI_NONE = 0,
	MYD_URI_PARSED = (1<<0),
	MYD_URI_FOUND_KEY = (1<<1),
	MYD_URI_MATCHED = (1<<2),
	MYD_URI_VALID = (1<<3)
} myd_uriflags;

struct myd_policy_s
{
	/* Print debugging information about certificate processing */
	int debug;
	myd_debug_handler debug_handler;
};

struct myd_cert_s
{
	myd_certtype type;
	union
	{
		X509 *x509;
	} c;
};

struct myd_key_s
{
	myd_keytype type;
	union
	{
		unsigned char *ptr;
		RSA *rsa;
		DSA *dsa;
		EC_KEY *ec;
		DH *dh;
	} k;
};

# if defined(__cplusplus)
extern "C" {
# endif

	myd *myd_from_pem(const char *pem, size_t len, const myd_policy *policy);
	myd *myd_from_pem_bio(BIO *bio, const myd_policy *policy);
	void myd_free(myd *myd);
	
	myd_certtype myd_get_certtype(myd *myd);
	myd_cert *myd_get_cert(myd *myd);
	X509 *myd_get_x509(myd *myd);
	
	myd_key *myd_get_key(myd *myd);
	myd_keytype myd_get_keytype(myd *myd);

	librdf_world *myd_get_librdf_world(myd *myd);
	librdf_storage *myd_get_librdf_storage(myd *myd);

	size_t myd_get_uri_count(myd *myd);
	const char *myd_get_uri(myd *myd, size_t index);
	myd_uriflags myd_get_uri_flags(myd *myd, size_t index);
	librdf_model *myd_get_uri_librdf_model(myd *myd, size_t index);
	
# if defined(__cplusplus)
}
# endif

#endif /*!MYD_H_*/
