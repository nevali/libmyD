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

int
myd__debug(const myd_policy *policy, int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if(policy && policy->debug_handler)
	{
		return policy->debug_handler(policy, level, fmt, ap);
	}
	return myd__debug_handler(policy, level, fmt, ap);
}

int
myd__debug_handler(const myd_policy *policy, int level, const char *fmt, va_list ap)
{
	int r;

	if(!policy || policy->debug == 0 || policy->debug < level)
	{
		return 0;
	}
	r = fprintf(stderr, "libmyD(%02d): ", level);
	r += vfprintf(stderr, fmt, ap);
	r += (fputc('\n', stderr) ? 1 : 0);
	return r;
}
