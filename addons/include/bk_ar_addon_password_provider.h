/* 
*
* Copyright (c) 2016 Attunity, Ltd.  All rights reserved.
*
* NOTICE:  All information contained herein is, and remains the property
* of Attunity Ltd.  The intellectual and technical concepts contained
* herein are proprietary to Attunity Ltd and may be covered by U.S. and
* Foreign Patents, patents in process, and are protected by trade secret
* or copyright law. Dissemination of this information or reproduction of
* this material is strictly forbidden unless prior written permission is
* obtained from Attunity Ltd.
* 
*/

#ifndef __AREP_ADDON_PASSWORD_PROVIDER_H__
#define __AREP_ADDON_PASSWORD_PROVIDER_H__

#include "ar_addon.h"

struct AR_AO_PASSWORD_PROVIDER_DEF_
{
	int		version;
	void	*userData;
	AR_ADDONS_STATUS (*get_secret_func)(char *name, const char *lookup_key, char *secret, int secret_len, char *principal, int principal_len);
};

#define GET_AR_AO_PASSWORD_PROVIDER_DEF() \
	AR_AO_CONTEXT->definitions->get_ar_ao_password_provider_def(AR_AO_CONTEXT->addonPool, AR_AO_VERSION);

#endif // __AREP_ADDON_PASSWORD_PROVIDER_H__
