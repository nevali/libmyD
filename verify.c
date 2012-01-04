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
#include <openssl/err.h>

#include "myD/myD.h"

int
main(int argc, char **argv)
{
	BIO *bin;
	myd *myd;
	size_t c;

	(void) argc;
	(void) argv;

	bin = BIO_new(BIO_s_file());
	setvbuf(stdin, NULL, _IONBF, 0);
	BIO_set_fp(bin, stdin, BIO_NOCLOSE);
	if(!(myd = myd_from_pem_bio(bin, NULL)))
	{
		fprintf(stderr, "%s: failed to parse certificate from standard input\n", argv[0]);
		ERR_print_errors_fp(stderr);
		return 1;
	}
	if(myd->x509)
	{
		printf("Parsed an X.509 certificate\n");
		printf("Certificate issuer DN:\n");
		X509_NAME_print_ex_fp(stdout, myd->x509->cert_info->issuer, 4, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
		printf("\nCertificate subject DN:\n");
		X509_NAME_print_ex_fp(stdout, myd->x509->cert_info->subject, 4, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
		fputc('\n', stdout);
	}
	if(myd->key)
	{
		switch(myd->key->type)
		{
		case EVP_PKEY_RSA:
			RSA_print_fp(stdout, myd->key->pkey.rsa, 0);
			break;
		default:
			printf("Unsupported public key type %d\n", myd->key->type);
		}
	}
	for(c = 0; c < myd->nuris; c++)
	{
		printf("Embedded URI #%d:\n", (int) c + 1);
		printf("    %s\n", myd->uris[c].uri);
		printf("      [%c] Parsed\n", myd->uris[c].parsed ? '+' : ' ');
		printf("      [%c] Found key statement\n", myd->uris[c].found_key ? '+' : ' ');
		printf("      [%c] Matched key to certificate\n", myd->uris[c].matched ? '+' : ' ');
		printf("      [%c] Valid according to policy\n", myd->uris[c].valid ? '+' : ' ');
	}
	myd_free(myd);
	return 0;
}

