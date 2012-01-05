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

static EVP_PKEY *process_key(myd *myd, librdf_world *world, librdf_model *model, librdf_node *subject, const myd_policy *policy);
static RSA *process_rsa_key(librdf_world *world, librdf_model *model, librdf_node *subject, const myd_policy *policy);
static int keys_match(EVP_PKEY *a, EVP_PKEY *b);
static BIGNUM *bn_from_node(librdf_node *node);
static int subject_isa(librdf_world *world, librdf_model *model, librdf_node *subject, const char *classuri);
static BIGNUM *bn_from_property(librdf_world *world, librdf_model *model, librdf_node *subject, const char *predicate);

/* Internal: Walk the list of URIs in a myD structure and retrieve structured data
 * about them.
 */

int
myd__traverse_uris(myd *myd, const myd_policy *policy)
{
	static librdf_world *world = NULL;
	static librdf_storage *storage = NULL;
	size_t c;
	librdf_parser *parser;
	librdf_uri *uri;
	librdf_statement *cert_query, *st;
	librdf_stream *stream;
	librdf_node *snode, *knode, *cert_key;
	EVP_PKEY *pkey;

	if(!world)
	{
		if(!(world = librdf_new_world()))
		{
			if(policy->debug)
			{
				fprintf(stderr, "libmyD: failed to create new Redland environment\n");
			}
			return -1;
		}
	}
	if(!storage)
	{
		if(!(storage = librdf_new_storage(world, "memory", NULL, NULL)))
		{
			if(policy->debug)
			{
				fprintf(stderr, "libmyD: failed to create new Redland memory store\n");
			}
			return -1;
		}
	}
	parser = librdf_new_parser(world, "guess", NULL, NULL);
	if(!parser)
	{
		if(policy->debug)
		{
			fprintf(stderr, "libmyD: failed to create Redland parser\n");
		}
		return -1;
	}
	cert_key = librdf_new_node_from_uri_string(world, (const unsigned char *) "http://www.w3.org/ns/auth/cert#key");
	for(c = 0; c < myd->nuris; c++)
	{
		uri = librdf_new_uri(world, (const unsigned char *) myd->uris[c].uri);
		snode = librdf_new_node_from_uri(world, uri);
		myd->uris[c].triples = librdf_new_model(world, storage, NULL);
		/* Attempt to fetch and parse the resource at uri */
		if(librdf_parser_parse_into_model(parser, uri, NULL, myd->uris[c].triples))
		{
			if(policy->debug)
			{
				fprintf(stderr, "libmyD: parsing of <%s> failed\n", myd->uris[c].uri);
			}
			continue;
		}
		myd->uris[c].parsed = 1;
		/* Find all of the triples matching URI cert:key ? */
		cert_query = librdf_new_statement_from_nodes(world, snode, librdf_new_node_from_node(cert_key), NULL);
		stream = librdf_model_find_statements(myd->uris[c].triples, cert_query);
		if(policy->debug && librdf_stream_end(stream))
		{
			fprintf(stderr, "libmyD: the subject <%s> does not have a cert:key property\n", myd->uris[c].uri);
		}
		while(!librdf_stream_end(stream))
		{
			st = librdf_stream_get_object(stream);
			knode = librdf_statement_get_object(st);
			if((pkey = process_key(myd, world, myd->uris[c].triples, knode, policy)))
			{
				myd->uris[c].found_key = 1;
				/* Compare the key with that presented in the certificate */
				if(keys_match(myd->key, pkey))
				{
					/* Successful match */
					myd->uris[c].matched = 1;
					EVP_PKEY_free(pkey);
					break;
				}
				else
				{
					if(policy->debug)
					{
						fprintf(stderr, "libmyD: the key associated with <%s> does not match the certificate\n", myd->uris[c].uri);
					}
				}
				EVP_PKEY_free(pkey);
			}
			librdf_stream_next(stream);
		}
		if(myd->uris[c].matched)
		{
			myd->uris[c].valid = 1;
		}
		librdf_free_stream(stream);
		librdf_free_statement(cert_query);
		librdf_free_uri(uri);
	}
	librdf_free_node(cert_key);
	return 0;
}

/* Process a subject to find a key matching that in myd->pkey */
static EVP_PKEY *
process_key(myd *myd, librdf_world *world, librdf_model *model, librdf_node *subject, const myd_policy *policy)
{
	RSA *rsa;
	EVP_PKEY *pkey;
	
	switch(myd->key->type)
	{
	case EVP_PKEY_RSA:
		if((rsa = process_rsa_key(world, model, subject, policy)))
		{
			pkey = EVP_PKEY_new();
			EVP_PKEY_assign_RSA(pkey, rsa);
			return pkey;
		}
		break;
	default:
		break;
	}
	return NULL;
}	

static RSA *
process_rsa_key(librdf_world *world, librdf_model *model, librdf_node *subject, const myd_policy *policy)
{
	BIGNUM *modulus, *exponent;
	RSA *rsa;
	unsigned char *p;

	modulus = NULL;
	exponent = NULL;
	if(!subject_isa(world, model, subject, "http://www.w3.org/ns/auth/cert#RSAPublicKey"))
	{
		if(policy->debug)
		{
			p = librdf_node_to_string(subject);
			fprintf(stderr, "libmyD: key node %s is not a cert:RSAPublicKey\n", (char *) p);
			free(p);
		}
		return NULL;
	}
	if(!(modulus = bn_from_property(world, model, subject, "http://www.w3.org/ns/auth/cert#modulus")))
	{
		if(policy->debug)
		{
			p = librdf_node_to_string(subject);
			fprintf(stderr, "libmyD: failed to obtain a multi-precision integer from cert:modulus property of %s\n", (char *) p);
			free(p);
		}
		return NULL;
	}
	if(!(exponent = bn_from_property(world, model, subject, "http://www.w3.org/ns/auth/cert#exponent")))
	{
		if(policy->debug)
		{
			p = librdf_node_to_string(subject);
			fprintf(stderr, "libmyD: failed to obtain a multi-precision integer from cert:exponent property of %s\n", (char *) p);
			free(p);
		}
		BN_free(modulus);
		return NULL;
	}
	rsa = RSA_new();
	if(rsa->n)
	{
		BN_free(rsa->n);
	}
	rsa->n = modulus;
	if(rsa->e)
	{
		BN_free(rsa->e);
	}
	rsa->e = exponent;
	return rsa;
}

/* Return 1 if the specified subject has the rdf:type named by classuri */
static int
subject_isa(librdf_world *world, librdf_model *model, librdf_node *subject, const char *classuri)
{
	librdf_node *predicate, *object;
	librdf_statement *query;
	librdf_stream *stream;
	int r;
	
	object = librdf_new_node_from_uri_string(world, (const unsigned char *) classuri);
	predicate = librdf_new_node_from_uri_string(world, (const unsigned char *) "http://www.w3.org/1999/02/22-rdf-syntax-ns#type");
	query = librdf_new_statement_from_nodes(world, librdf_new_node_from_node(subject), predicate, object);
	stream = librdf_model_find_statements(model, query);
	if(librdf_stream_end(stream))
	{
		r = 0;
	}
	else
	{
		r = 1;
	}
	librdf_free_statement(query);
	librdf_free_stream(stream);
	return r;
}

/* Return 1 if the public keys in a and b are equivalent */
static int
keys_match(EVP_PKEY *a, EVP_PKEY *b)
{
	if(a->type != b->type)
	{
		return 0;
	}
	switch(a->type)
	{
	case EVP_PKEY_RSA:
		if(!BN_cmp(a->pkey.rsa->n, b->pkey.rsa->n) &&
		   !BN_cmp(a->pkey.rsa->e, b->pkey.rsa->e))
		{
			return 1;
		}
		return 0;
	}
	return -1;
}

/* Locate a literal with the specified predicate on a subject and return
 * its value as a BIGNUM.
 */
static BIGNUM *
bn_from_property(librdf_world *world, librdf_model *model, librdf_node *subject, const char *predicateuri)
{
	BIGNUM *bn;
	librdf_node *predicate, *obj;
	librdf_statement *query, *st;
	librdf_stream *stream;

	bn = NULL;
	predicate = librdf_new_node_from_uri_string(world, (const unsigned char *) predicateuri);
	query = librdf_new_statement_from_nodes(world, librdf_new_node_from_node(subject), predicate, NULL);
	stream = librdf_model_find_statements(model, query);
	while(!librdf_stream_end(stream))
	{
		st = librdf_stream_get_object(stream);
		obj = librdf_statement_get_object(st);
		if((bn = bn_from_node(obj)))
		{
			break;
		}
		librdf_stream_next(stream);
	}
	librdf_free_stream(stream);
	librdf_free_statement(query);
	return bn;
}

/* Parse a literal into a new BIGNUM, or return NULL on error */
static BIGNUM *
bn_from_node(librdf_node *node)
{
	BIGNUM *num;
	librdf_uri *dt;

	if(!librdf_node_is_literal(node))
	{
		return NULL;
	}
	dt = librdf_node_get_literal_value_datatype_uri(node);
	if(!dt)
	{
		/* Untyped literals are no use */
		return NULL;
	}
	num = NULL;
	if(!strcmp((const char *) librdf_uri_to_string(dt), "http://www.w3.org/2001/XMLSchema#hexBinary"))
	{
		BN_hex2bn(&num, (const char *) librdf_node_get_literal_value(node));
		return num;
	}
	if(!strcmp((const char *) librdf_uri_to_string(dt), "http://www.w3.org/2001/XMLSchema#integer"))
	{
		BN_dec2bn(&num, (const char *) librdf_node_get_literal_value(node));
		return num;
	}
	/* Some other kind of literal */
	return NULL;
}



