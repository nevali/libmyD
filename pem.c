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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "p_libmyD.h"

/* Read a PEM-formatted WebID certificate and process the URIs within it */
myd *
myd_from_pem(const char *pem, size_t len, const myd_policy *policy)
{
	BIO *bmem;
	myd *myd;

	if(!(bmem = BIO_new(BIO_s_mem())))
	{
		return NULL;
	}
	if(BIO_write(bmem, pem, len) != (ssize_t) len)
	{
		BIO_free(bmem);
		return NULL;
	}
	(void) BIO_seek(bmem, 0);
	myd = myd_from_pem_bio(bmem, policy);
	BIO_free(bmem);
	return myd;
}

myd *
myd_from_pem_bio(BIO *bio, const myd_policy *policy)
{
	myd *myd;
	GENERAL_NAMES *names;
	GENERAL_NAME *name;
	unsigned char *utf8;
	size_t count, n;

	if(!policy)
	{
		policy = &myd__default_policy;
	}

	if(!(myd = myd__new()))
	{
		return NULL;
	}
	if(!(myd->x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)))
	{
		if(policy->debug)
		{
			fprintf(stderr, "libmyD: failed to parse PEM-formatted X.509 certificate\n");
		}
		myd_free(myd);
		return NULL;
	}
	myd->key = X509_get_pubkey(myd->x509);
	/* Extract the subjectAltName entries and create URI structures for each */
	names = X509_get_ext_d2i(myd->x509, NID_subject_alt_name, 0, 0);
	if(names)
	{
		count = sk_GENERAL_NAME_num(names);
		for(n = 0; n < count; n++)
		{
			name = sk_GENERAL_NAME_value(names, n);
			if(name->type == GEN_URI)
			{
				ASN1_STRING_to_UTF8(&utf8, name->d.uniformResourceIdentifier);
				myd__add_uri(myd, (const char *) utf8);
			}
		}
		if(policy->debug)
		{
			if(!myd->nuris)
			{
				fprintf(stderr, "libmyD: none of the certificate's subjectAltName entries are URIs\n");
			}
		}
	}
	else
	{
		if(policy->debug)
		{
			fprintf(stderr, "libmyD: certificate does not contain any subjectAltName extension\n");
		}
	}
	myd__traverse_uris(myd, policy);
	return myd;
}
