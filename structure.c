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

#include "p_libmyd.h"

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
		if(myd->x509)
		{
			X509_free(myd->x509);
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
	myd->nuris++;
	p->uri = uri;
	return p;
}
