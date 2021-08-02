//	   Sample for a custom password provider addon
//
//   Copyright (c) 2019, Attunity Ltd.
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

#include <stdio.h>
#include <string.h>
#include "ar_addon.h"
#include "ar_addon_transformation.h"
#include "ar_addon_password_provider.h"

#define	STREQ(A,B)	(strcmp((A), (B)) == 0)

static AR_ADDONS_STATUS get_secret(const char *name, const char *lookup_key, char *secret, int secret_len, char *principal, int principal_len);

static void string_copy(char *dest, const char *src, int len) {
#ifdef _WIN32
	strcpy_s(dest, len, src);	
#else
	strncpy(dest, src, len);
#endif
}

AR_AO_EXPORTED int ar_addon_init(AR_ADDON_CONTEXT *context)
{
	AR_AO_PASSWORD_PROVIDER_DEF *passwordProviderdef = NULL;

	AR_AO_INIT(context);

	passwordProviderdef = GET_AR_AO_PASSWORD_PROVIDER_DEF();
	passwordProviderdef->get_secret_func = get_secret;
	AR_AO_REGISRATION->register_password_provider(passwordProviderdef);
	return 0;
}

/*
* name – the name of the secret field (‘password’, ‘s3SecretKey’, etc…)
* lookup_key – the text the user wrote after the ‘lookup::’
* secret – the buffer for the fetched secret.
* secret_len – the allocated length of the secret buffer
* principal – the associated principal (e.g. user). On input the current principal on output the fetched one
* principal_len – the allocated length of the principal buffer
*/
static AR_ADDONS_STATUS get_secret(const char *name, const char *lookup_key, char *secret, int secret_len, char *principal, int principal_len)
{
	// The "ADDONS" logger must be set to trace level or above to see trace messages.
	// All messages should indicate the source is this addon (e.g. the prefix "VaultX-Addon: ").
	// If the lookup_key may contain sensitive information, it must not be logged.
	AR_AO_LOG->log_trace("VaultX-Addon: Requested secret for '%s'", lookup_key);

	// Handling for secret fields named 'password'
	if (STREQ(name, "password"))
	{
		// This simulates lookup failure by having the user enter "lookup::fail" in the secret field (e.g. a password field),
		// The proper behavior is to return AR_ADDONS_STATUS_FAILED.
		if (STREQ(lookup_key, "fail"))
		{
			char *vault_error = "VaultX service not set up ... or something similar ...";
			AR_AO_LOG->log_error("VaultX-Addon: Failed to look up credentials for '%s'. %s", lookup_key, vault_error);
			return AR_ADDONS_STATUS_FAILED;
		}

		// This simulates a case where both the principal and secret need to be assigned. If in some cases the
		// principal needs to be assigned a value while in other cases not, then the lookup_key value should
		// indicate it somehow. In the case here, if the lookup starts with '+' it is taken to mean both principal
		// and secret need to be filled.
		//
		// Note that overriding the principal is not supported for all endpoint types.
		if (*lookup_key == '+')
		{
			// The clear text secret (and preferably the principal) should not remain in memory once this function
			// returns other than in the return parameters. The example here obviously violates this but in a proper
			// implementation the secret, secret_len, principal, principal_len parameters can be directly passed to
			// the underlying vault software and this way, the data will be cleared from memory automatically once
			// it have been used.
			//
			// Additionally, it is important to check for errors from the underlying vault are return them as silent 
			// failures are very hard to troubleshoot.
			string_copy(principal, "db_user", principal_len);
			string_copy(secret, "db_password", secret_len);

			// If the lookup_key may contain sensitive information, it must not be logged.
			// The secret must never be logged!
			AR_AO_LOG->log_trace("VaultX-Addon: Returned user '%s' and password '*****' for lookup key '%s'", principal, lookup_key);
		}
		else
		{
			// Use the user name from the endpoint settings as principal,
			// and only return the password.
			string_copy(secret, "db_password", secret_len);

			// If the lookup_key may contain sensitive information, it must not be logged.
			// The secret must never be logged!
			AR_AO_LOG->log_trace("VaultX-Addon: Returned password '*****' for user '%s' and lookup key '%s'", principal, lookup_key);
		}
	}
	// Handling for specific secret field named 's3SecretKey' - both principal name and credentials are filled
	else if (STREQ(name, "s3SecretKey"))
	{
		// Override the principal defined in the endpoint settings to AKIAIFNTZA5I26266QSA,
		// and set the password.
		string_copy(principal, "AKIAIFNTZA5I26266QSA", principal_len);
		string_copy(secret, "v014GZaAAvAeLJwsmZZmkBj7iUKkT/s+ZhmWW5L", secret_len);
	}

	return AR_ADDONS_STATUS_SUCCESS;
}
