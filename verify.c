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

#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <openssl/err.h>

#include "myD/myD.h"

#if !defined(HAVE_ISATTY) && defined(HAVE__ISATTY)
# define isatty(fd)                     _isatty(fd)
#elif !defined(HAVE_ISATTY)
# define isatty(fd)                     0
#endif

static myd_policy policy;

int
main(int argc, char **argv)
{
	BIO *bin;
	X509 *x509;
	myd *myd;
	myd_key *key;
	myd_uriflags flags;
	const char *uri;
	size_t c, nuris;

	(void) argc;
	(void) argv;

	if(argc > 1)
	{
		fprintf(stderr, "Usage: %s < CERTIFICATE.pem\n", argv[0]);
		return 1;
	}
	if(isatty(0))
	{
		fprintf(stderr, "%s: Warning: Reading from standard input\n", argv[0]);
	}
	bin = BIO_new(BIO_s_file());
	setvbuf(stdin, NULL, _IONBF, 0);
	BIO_set_fp(bin, stdin, BIO_NOCLOSE);

	policy.debug = 65535;

	if(!(myd = myd_from_pem_bio(bin, &policy)))
	{
		fprintf(stderr, "%s: failed to parse certificate from standard input\n", argv[0]);
		ERR_print_errors_fp(stderr);
		return 1;
	}
	x509 = myd_get_x509(myd);
	if(x509)
	{
		printf("Parsed an X.509 certificate\n");
		printf("Certificate issuer DN:\n");
		X509_NAME_print_ex_fp(stdout, x509->cert_info->issuer, 4, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
		printf("\nCertificate subject DN:\n");
		X509_NAME_print_ex_fp(stdout, x509->cert_info->subject, 4, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
		fputc('\n', stdout);
	}
	key = myd_get_key(myd);
	if(key)
	{
		switch(key->type)
		{
		case MYD_KT_RSA:
			RSA_print_fp(stdout, key->k.rsa, 0);
			break;
		default:
			printf("Unsupported public key type %d\n", key->type);
		}
	}
	nuris = myd_get_uri_count(myd);
	for(c = 0; c < nuris; c++)
	{
		printf("Embedded URI #%d:\n", (int) c + 1);
		uri = myd_get_uri(myd, c);
		flags = myd_get_uri_flags(myd, c);
		printf("    %s\n", uri);
		printf("      [%c] Parsed\n", (flags & MYD_URI_PARSED) ? '+' : ' ');
		printf("      [%c] Found key statement\n", (flags & MYD_URI_FOUND_KEY) ? '+' : ' ');
		printf("      [%c] Matched key to certificate\n", (flags & MYD_URI_MATCHED) ? '+' : ' ');
		printf("      [%c] Valid according to policy\n", (flags & MYD_URI_VALID) ? '+' : ' ');
	}
	myd_free(myd);
	return 0;
}

