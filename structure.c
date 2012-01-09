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

/* Internal: allocate a new myD structure */
myd *
myd__new(void)
{
	return (myd *) calloc(1, sizeof(myd));
}

/* Free the resources associated with a myD structure */
void
myd_free(myd *myd)
{
	if(myd)
	{
		if(myd->cert.type == MYD_CT_X509)
		{
			X509_free(myd->cert.c.x509);
		}
		free(myd);
	}
}

/* Internal: Add a new URI to a myD structure */
myd_uri *
myd__add_uri(myd *myd, const char *uri)
{
	myd_uri *p;
	
	p = (myd_uri *) realloc(myd->uris, sizeof(myd_uri) * (myd->nuris + 1));
	if(!p)
	{
		return NULL;
	}
	myd->uris = p;
	p = &(myd->uris[myd->nuris]);   
	memset(p, 0, sizeof(myd_uri));
	myd->nuris++;
	p->uri = uri;
	return p;
}

/* Internal: Assign an X.509 certificate to a myD structure */
int
myd__assign_x509(myd *dest, X509 *src)
{
	EVP_PKEY *key;
	
	dest->cert.type = MYD_CT_X509;
	dest->cert.c.x509 = src;
	key = X509_get_pubkey(src);
	return myd__assign_evp_pkey(dest, key);
}

/* Internal: Assign an EVP_PKEY to a myD structure */
int
myd__assign_evp_pkey(myd *dest, EVP_PKEY *src)
{
	dest->key.type = src->type;
	dest->key.k.ptr = (unsigned char *) src->pkey.ptr;
	return 0;
}

/* Return the type of the certificate represented by the myD structure */
myd_certtype
myd_get_certtype(myd *myd)
{
	return myd->cert.type;
}

/* Return the certificate represented by the myD structure */
myd_cert *
myd_get_cert(myd *myd)
{
	return &(myd->cert);
}

/* If the myD structure contains an X.509 certificate, return it */
X509 *
myd_get_x509(myd *myd)
{
	if(myd->cert.type == MYD_CT_X509)
	{
		return myd->cert.c.x509;
	}
	return NULL;
}

/* Return the type of the key represented by the myD structure */
myd_keytype
myd_get_keytype(myd *myd)
{
	return myd->key.type;
}

/* Return the certificate represented by the myD structure */
myd_key *
myd_get_key(myd *myd)
{
	return &(myd->key);
}

/* Return the number of URIs associated with the myD structure */
size_t
myd_get_uri_count(myd *myd)
{
	return myd->nuris;
}

/* Return the URI string at URI <index> */
const char *
myd_get_uri(myd *myd, size_t index)
{
	if(index < myd->nuris)
	{
		return myd->uris[index].uri;
	}
	return NULL;
}

/* Return the flags for URI <index> */
myd_uriflags
myd_get_uri_flags(myd *myd, size_t index)
{
	if(index < myd->nuris)
	{
		return myd->uris[index].flags;
	}
	return MYD_URI_NONE;
}

/* Return the Redland model for URI <index> */
librdf_model *
myd_get_uri_librdf_model(myd *myd, size_t index)
{
	if(index < myd->nuris)
	{
		return myd->uris[index].triples;
	}
	return NULL;
}
