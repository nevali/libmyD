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

# include "myD/myD.h"

extern myd *myd__new(void);
extern myd_uri *myd__add_uri(myd *myd, const char *uri);
extern int myd__traverse_uris(myd *myd, myd_policy *reserved);

#endif /*!P_LIBMYD_H_*/
