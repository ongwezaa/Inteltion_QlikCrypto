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

#ifndef __AREP_ADDON_TRANSFORMATION_H__
#define __AREP_ADDON_TRANSFORMATION_H__

#include "sqlite3.h"
#include "ar_addon.h"

struct AR_ADDONS_SQLITE_
{
	void*					(*sqlite3_user_data)(sqlite3_context*);
	void					(*sqlite3_result_double)(sqlite3_context*, double);
	void					(*sqlite3_result_error)(sqlite3_context*, const char*, int);
	void					(*sqlite3_result_error_toobig)(sqlite3_context*);
	void					(*sqlite3_result_error_nomem)(sqlite3_context*);
	void					(*sqlite3_result_error_code)(sqlite3_context*, int);
	void					(*sqlite3_result_int)(sqlite3_context*, int);
	void					(*sqlite3_result_int64)(sqlite3_context*, sqlite3_int64);
	void					(*sqlite3_result_null)(sqlite3_context*);
	void					(*sqlite3_result_text)(sqlite3_context*, const char*, int, void(*)(void*));	
	void					(*sqlite3_result_blob)(sqlite3_context*, const void*, int, void(*)(void*));
	void					(*sqlite3_result_zeroblob)(sqlite3_context*, int n);
	const void*				(*sqlite3_value_blob)(sqlite3_value*);
	int						(*sqlite3_value_bytes)(sqlite3_value*);
	int						(*sqlite3_value_bytes16)(sqlite3_value*);
	double					(*sqlite3_value_double)(sqlite3_value*);
	int						(*sqlite3_value_int)(sqlite3_value*);
	sqlite3_int64			(*sqlite3_value_int64)(sqlite3_value*);
	const unsigned char*	(*sqlite3_value_text)(sqlite3_value*);
	int						(*sqlite3_value_type)(sqlite3_value*);
	int						(*sqlite3_value_numeric_type)(sqlite3_value*);
};


struct AR_AO_TRANSFORMATION_DEF_
{
	int		version;
	char	*displayName;	// e.g. "trim(X,Y)"
	char	*functionName;	// e.g. "trim"
	char	*description;	// e.g. "The trim(X,Y) function returns a string formed by removing any and all characters that appear in Y from both ends of X. If the Y argument is omitted, trim(X) removes spaces from both ends of X."
	int		nArgs;			// e.g. 2
	void	*userData;
	void	(*func)(sqlite3_context*, int, sqlite3_value**);
};

#define GET_AR_AO_TRANSFORMATION_DEF() \
	AR_AO_CONTEXT->definitions->get_ar_ao_transformation_def(AR_AO_CONTEXT->addonPool, AR_AO_VERSION);

#endif // __AREP_ADDON_TRANSFORMATION_H__
