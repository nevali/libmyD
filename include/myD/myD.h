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

# include <openssl/evp.h>
# include <openssl/x509.h>
# include <openssl/bio.h>

# include <redland.h>

typedef struct myd_s myd;
typedef struct myd_uri_s myd_uri;
typedef void *myd_policy; /* Placeholder */

struct myd_s
{
	X509 *x509;
	EVP_PKEY *key;
	size_t nuris;
	myd_uri *uris;
};

struct myd_uri_s
{
	const char *uri;
	const char *content_type;
	librdf_model *triples;
	/* Per-URI status */
	int parsed:1;
	int found_key:1;
	int matched:1;
	int valid:1;
};

# if defined(__cplusplus)
extern "C" {
# endif

	myd *myd_from_pem(const char *pem, size_t len, myd_policy *reserved);
	myd *myd_from_pem_bio(BIO *bio, myd_policy *reserved);
	void myd_free(myd *myd);

# if defined(__cplusplus)
}
# endif

#endif /*!MYD_H_*/
