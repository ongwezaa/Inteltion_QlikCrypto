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

#ifndef __AREP_ADDON_H__
#define __AREP_ADDON_H__

#if defined(_WIN32)
// windows specific
#include <windows.h>
#define AR_AO_EXPORTED __declspec(dllexport)
#else
#define AR_AO_EXPORTED
#endif

#define AR_AO_VERSION 1

typedef enum AR_ADDONS_STATUS_
{
	AR_ADDONS_STATUS_SUCCESS = 0,
	AR_ADDONS_STATUS_FAILED = 1,
} AR_ADDONS_STATUS;

typedef void AR_AO_MPOOL;

typedef AR_ADDONS_STATUS(*AR_ADDONS_MEM_CTX_CLEANUP)(void *data);
typedef struct AR_ADDONS_MEMORY_
{
	/* creating of a new memory pool
	* @param parentPool The pool to allocate out of (mandatory)
	* @param poolName The new memory pool name(title) (optional)
	*	   	 poolName value assumed to be a static, unmanaged space that does not need to be freed.
	*		 value will not be copied internaly.
	* @param newPool  Returns The new memory pool
	* @return Status
	*/
	AR_ADDONS_STATUS(*create_pool)(AR_AO_MPOOL *parentPool, char *poolName, AR_AO_MPOOL **newPool);

	// * Note: using clear_pool has a performance benefit than using destroy & create.
	/* deleting the given pool and deallocation the memory associated with it 
	* @param pool	The pool to destroy
	* @return Status
	*/
	AR_ADDONS_STATUS(*destroy_pool)(AR_AO_MPOOL **pool);

	/* deallocation of the memory associated with a pool
	* @param pool	The pool to clear
	* @return Status
	*/
	AR_ADDONS_STATUS(*clear_pool)(AR_AO_MPOOL *pool);

	/*allocation of memory from a given pool
	* NOTE: it's not thread safe on the same pool. different pools can be used
	        to allocate memory on multipule threads on the same time.
	* allocate a buffer and set all bytes to zero
	* abort process in case there is no memory
	* @param pool	The pool to allocate memory from
	* @param size	The size of the buffer to allocate
	* @return Status
	*/
	void                *(*calloc)(AR_AO_MPOOL *pool, size_t size);

	//the use of ctx pool per thread will protect from crash since each addon will have his own pool allocator
	/*returns thread ctx pool (create new pool if needed).
	* pool will be destroyed automatically when thread exists.
	* @param addonName	The pool name if still there isn't one and need to be crated (optional)
	* @param pool		ctx pool that the function retuns
	*/
	AR_ADDONS_STATUS(*get_ctx_pool)(char *addonName, AR_AO_MPOOL **pool);

	/* Methods for get metadata on the pool.
	* @param pool	The ctx pool to get metadata from
	* @param key	The key for the metadata to retrieve
	* @param data	The user metadata associated with the pool(returned).
	* @return Status
	*/
	AR_ADDONS_STATUS(*get_ctx)(AR_AO_MPOOL *pool, char *key, void **data);

	/*	Methods for set metadata on the thread pool.
	* @param pool	The ctx pool
	* @param key	The key for the metadata to retrieve
	* @param data	The user metadata to be associated with the pool
	* @param cleanup The cleanup method will be called to clean the data when pool is destroyed.
	method shall return 0 on success
	* @return Status
	*
	* Note :  @warning The data to be attached to the pool should have a life span
	*          at least as long as the pool it is being attached to.
	*/
	AR_ADDONS_STATUS(*set_ctx)(AR_AO_MPOOL *pool, char *key, void *data, AR_ADDONS_MEM_CTX_CLEANUP cleanup);

} AR_ADDONS_MEMORY;

typedef struct AR_ADDONS_LOG_
{
	//NOTE **** for all the log messages to be seen need to turn the "ADDONS" (in the log settings) to the relevant level of log.
	// *Note: pointers should use %pp in the strFormat 

	/*write an error to the log
	* @param strFormat	the error msg format 
	* ... args (if there is)
	* @return Status
	*/
	AR_ADDONS_STATUS(*log_error)(const char *strFormat, ...);

	/* write a warning to the log
	* @param strFormat	the error msg format
	* ... args (if there is)
	* @return Status
	*/
	AR_ADDONS_STATUS(*log_warning)(const char *strFormat, ...);

	/*write a trace message to the log
	* @param strFormat	The error msg format
	* ... args (if there is)
	* @return Status
	*/
	AR_ADDONS_STATUS(*log_trace)(const char *strFormat, ...);
} AR_ADDONS_LOG;

typedef struct AR_ADDONS_SQLITE_ AR_ADDONS_SQLITE;
typedef struct AR_ADDONS_UTILS_
{
	AR_ADDONS_MEMORY    *memory;
	AR_ADDONS_LOG       *log;
	AR_ADDONS_SQLITE    *sqlite;
} AR_ADDONS_UTILS;

typedef struct AR_AO_TRANSFORMATION_DEF_        AR_AO_TRANSFORMATION_DEF;
typedef struct AR_AO_PASSWORD_PROVIDER_DEF_     AR_AO_PASSWORD_PROVIDER_DEF;
typedef struct AR_AO_CUSTOM_LOGGER_DEF_         AR_AO_CUSTOM_LOGGER_DEF;

//need to call registe in the init function 
typedef struct AR_ADDONS_REGISRATION_
{
	AR_ADDONS_STATUS(*register_user_defined_transformation)(AR_AO_TRANSFORMATION_DEF *definition);
	AR_ADDONS_STATUS(*register_password_provider)(AR_AO_PASSWORD_PROVIDER_DEF *definition);
	AR_ADDONS_STATUS(*register_custom_logger)(AR_AO_CUSTOM_LOGGER_DEF *definition);
}AR_ADDONS_REGISRATION;

typedef struct AR_ADDONS_DEFINITION_
{
	AR_AO_TRANSFORMATION_DEF    *(*get_ar_ao_transformation_def)(AR_AO_MPOOL *pool, int version);
	AR_AO_PASSWORD_PROVIDER_DEF *(*get_ar_ao_password_provider_def)(AR_AO_MPOOL *pool, int version);
	AR_AO_CUSTOM_LOGGER_DEF     *(*get_ar_ao_custom_logger_def)(AR_AO_MPOOL *pool, int version);
} AR_ADDONS_DEFINITION;


typedef struct AR_ADDONS_CONTEXT_
{
	//addons dir (name)
	char                        *addonDir;
	//pool 
	AR_AO_MPOOL                 *addonPool;
	//difinitions
	AR_ADDONS_UTILS             *utils;
	AR_ADDONS_REGISRATION       *registrations;
	AR_ADDONS_DEFINITION        *definitions;
	// arguments 
	char                        **argv;
	// arguments count
	int                         argc;
} AR_ADDON_CONTEXT;

#ifndef __cplusplus
AR_ADDON_CONTEXT        *AR_AO_CONTEXT;
AR_ADDONS_MEMORY        *AR_AO_MEM;
AR_ADDONS_SQLITE        *AR_AO_SQLITE;
AR_ADDONS_LOG           *AR_AO_LOG;
AR_ADDONS_REGISRATION   *AR_AO_REGISRATION;
#endif


#define AR_AO_INIT(CONTEXT) \
    AR_AO_CONTEXT           = CONTEXT; \
    AR_AO_MEM               = CONTEXT->utils->memory; \
    AR_AO_SQLITE            = CONTEXT->utils->sqlite; \
    AR_AO_LOG               = CONTEXT->utils->log;	  \
    AR_AO_REGISRATION       = CONTEXT->registrations; \

typedef AR_AO_EXPORTED AR_ADDONS_STATUS AR_ADDON_INIT_FUNC(AR_ADDON_CONTEXT *context);

#endif // __AREP_ADDON__
