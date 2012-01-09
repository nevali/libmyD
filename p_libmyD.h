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

#ifndef P_LIBMYD_H_
# define P_LIBMYD_H_                    1

# include <stdio.h>
# include <string.h>

# include <openssl/bio.h>
# include <openssl/buffer.h>
# include <openssl/x509.h>
# include <openssl/pem.h>
# include <openssl/x509v3.h>
# include <openssl/bn.h>
# include <openssl/rsa.h>

# include <redland.h>

# define MYD_INTERNAL_                  1

# include "myD/myD.h"

typedef struct myd_uri_s myd_uri;

struct myd_s
{
	myd_cert cert;
	myd_key key;
	size_t nuris;
	myd_uri *uris;
	librdf_world *world;
	librdf_storage *storage;
	int world_alloc:1;
	int storage_alloc:1;
};

struct myd_uri_s
{
	const char *uri;
	const char *content_type;
	librdf_model *triples;
	myd_uriflags flags;
};

extern myd_policy myd__default_policy;

extern myd *myd__new(void);
extern myd_uri *myd__add_uri(myd *myd, const char *uri);
extern int myd__assign_x509(myd *dest, X509 *src);
extern int myd__assign_evp_pkey(myd *dest, EVP_PKEY *src);

extern int myd__traverse_uris(myd *myd, const myd_policy *policy);



extern int myd__debug(const myd_policy *policy, int level, const char *fmt, ...);
extern int myd__debug_handler(const myd_policy *policy, int level, const char *fmt, va_list ap);

#endif /*!P_LIBMYD_H_*/
