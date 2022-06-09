#include <stdio.h>
#include <string.h>
#include "ar_addon.h"
#include "ar_addon_transformation.h"

#include <openssl/aes.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#pragma warning(disable : 4996)
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")

#define CURL_STATICLIB

#include <stdio.h>
#include <curl/curl.h>

const char* cfFileName = "plt_config.json";

const char* cfMisTokenUri = "plt_mis_token_uri";
const char* cfMisKvUri = "plt_mis_kv_uri";

const char* poolKeyName = "pltkv";
const char* poolKeyVersionName = "pltkvver";
const char* poolKeyIdName = "pltkvidname";

char* concatenate(char* a, char* b, char* c)
{
	int size = strlen(a) + strlen(b) + strlen(c) + 1;
	char* str = malloc(size);
	strcpy(str, a);
	strcat(str, b);
	strcat(str, c);

	return str;
}

typedef struct {
	unsigned char* buffer;
	size_t len;
	size_t buflen;
} get_request;

#define CHUNK_SIZE 2048

size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata)
{
	size_t realsize = size * nmemb;
	get_request* req = (get_request*)userdata;
	while (req->buflen < req->len + realsize + 1)
	{
		req->buffer = realloc(req->buffer, req->buflen + CHUNK_SIZE);
		req->buflen += CHUNK_SIZE;
	}
	memcpy(&req->buffer[req->len], ptr, realsize);
	req->len += realsize;
	req->buffer[req->len] = 0;

	return realsize;
}

void removeChar(char* str, char garbage) {
	char* src, * dst;
	for (src = dst = str; *src != '\0'; src++) {
		*dst = *src;
		if (*dst != garbage) dst++;
	}
	*dst = '\0';
}

char* ltrim(char* s)
{
	while (isspace(*s)) s++;
	return s;
}

char* rtrim(char* s)
{
	char* back = s + strlen(s);
	while (isspace(*--back));
	*(back + 1) = '\0';
	return s;
}

char* trim(char* s)
{
	return rtrim(ltrim(s));
}

char* get_value_json(char* ptr, char* name) {
	char* str = "";
	removeChar(ptr, '{');
	removeChar(ptr, '}');
	removeChar(ptr, '"');
	char* spltValue = strtok(ptr, ",");

	// loop through the string to extract all other tokens
	while (spltValue != NULL) {
		if (strstr(spltValue, name) != NULL)
		{
			spltValue = strchr(spltValue, ':');
			if (spltValue == NULL) {
				break;
			}
			spltValue++;
			str = trim(spltValue);
		}
		spltValue = strtok(NULL, ",");
	}
	return str;
}

char* get_curl_value(struct curl_slist* headers, char* requri, char* name) {
	char* str = "";

	CURL* curl;
	CURLcode res;
	curl_global_init(CURL_GLOBAL_ALL);

	get_request req = { .buffer = NULL, .len = 0, .buflen = 0 };

	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, requri);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		req.buffer = malloc(CHUNK_SIZE);
		req.buflen = CHUNK_SIZE;

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&req);
		res = curl_easy_perform(curl);

		char* ptr = req.buffer;
		str = get_value_json(ptr, name);

		/* always cleanup */
		curl_easy_cleanup(curl);
	}

	return str;
}

int split(const char* txt, char delim, char*** tokens)
{
	int* tklen, * t, count = 1;
	char** arr, * p = (char*)txt;

	while (*p != '\0') if (*p++ == delim) count += 1;
	t = tklen = calloc(count, sizeof(int));
	for (p = (char*)txt; *p != '\0'; p++) *p == delim ? *t++ : (*t)++;
	*tokens = arr = malloc(count * sizeof(char*));
	t = tklen;
	p = *arr++ = calloc(*(t++) + 1, sizeof(char*));
	while (*txt != '\0')
	{
		if (*txt == delim)
		{
			p = *arr++ = calloc(*(t++) + 1, sizeof(char*));
			txt++;
		}
		else *p++ = *txt++;
	}
	free(tklen);
	return count;
}

char* keyVersion = "";
char* keyId = "";

char* auth_plt_gen_key()
{
	// Get file config path
	char* cfPath = concatenate(AR_AO_CONTEXT->addonDir, "\\", cfFileName);

	// Read config file
	char cf[1024];
	char cfTmp[1024];
	FILE* fileCf;
	size_t nread;

	fileCf = fopen(cfPath, "r");
	if (fileCf) {
		while ((nread = fread(cf, 1, sizeof cf, fileCf)) > 0)
			fwrite(cf, 1, nread, stdout);
		if (ferror(fileCf)) {
			/* deal with error */
		}
		fclose(fileCf);
	}

	strcpy(cfTmp, cf);
	char* cfTokenUri = get_value_json(cfTmp, cfMisTokenUri);
	AR_AO_LOG->log_trace(cfTokenUri);
	strcpy(cfTmp, cf);
	char* cfKvUri = get_value_json(cfTmp, cfMisKvUri);
	AR_AO_LOG->log_trace(cfKvUri);
	//

	// Start get key from key vault
	char* key = "";
	

	// Get token from managed identity
	struct curl_slist* tokenHeaders = NULL;
	tokenHeaders = curl_slist_append(tokenHeaders, "metadata: true");
	char* token = get_curl_value(tokenHeaders, cfTokenUri, "access_token");

	// Get key vault
	struct curl_slist* kvHeaders = NULL;
	char* auth = concatenate("Authorization: Bearer ", token, "");
	kvHeaders = curl_slist_append(kvHeaders, auth);

	key = get_curl_value(kvHeaders, cfKvUri, "value");
	keyVersion = get_curl_value(kvHeaders, cfKvUri, "id");

	char** tokens;
	int count, i;

	count = split(keyVersion, '/', &tokens);
	for (i = 0; i < count; i++) {
		if (i == count - 2) {
			keyId = tokens[i];
		}
	}
	/* freeing tokens */
	//for (i = 0; i < count; i++) free(tokens[i]);
	//free(tokens);


	memset(cf, 0x00, 1024);
	memset(cfTmp, 0x00, 1024);

	return key;
}

static char encoding_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
								'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
								'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
								'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
								'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
								'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
								'w', 'x', 'y', 'z', '0', '1', '2', '3',
								'4', '5', '6', '7', '8', '9', '+', '/' };
static char* decoding_table = NULL;
static int mod_table[] = { 0, 2, 1 };

void build_decoding_table() {

	decoding_table = malloc(256);

	for (int i = 0; i < 64; i++)
		decoding_table[(unsigned char)encoding_table[i]] = i;
}

void base64_cleanup() {
	free(decoding_table);
}

char* base64_encode(const unsigned char* data,
	size_t input_length,
	size_t* output_length) {

	*output_length = 4 * ((input_length + 2) / 3);

	char* encoded_data = malloc(*output_length + 1);
	if (encoded_data == NULL) return NULL;

	for (int i = 0, j = 0; i < input_length;) {

		uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (int i = 0; i < mod_table[input_length % 3]; i++)
		encoded_data[*output_length - 1 - i] = '=';

	encoded_data[*output_length] = 0;
	return encoded_data;
}

unsigned char* base64_decode(const char* data,
	size_t input_length,
	size_t* output_length) {

	if (decoding_table == NULL) build_decoding_table();

	if (input_length % 4 != 0) return NULL;

	*output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '=') (*output_length)--;
	if (data[input_length - 2] == '=') (*output_length)--;

	unsigned char* decoded_data = malloc(*output_length);
	if (decoded_data == NULL) return NULL;

	for (int i = 0, j = 0; i < input_length;) {

		uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

		uint32_t triple = (sextet_a << 3 * 6)
			+ (sextet_b << 2 * 6)
			+ (sextet_c << 1 * 6)
			+ (sextet_d << 0 * 6);

		if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
	}

	return decoded_data;
}

#define ASCII_START 32
#define ASCII_END 126
char* generateRandomString(int size) {
	int i;
	char* res = malloc(size + 1);
	for (i = 0; i < size; i++) {
		res[i] = (char)(rand() % (ASCII_END - ASCII_START)) + ASCII_START;
	}
	res[i] = '\0';
	return res;
}

static void encrypt_aes(AR_ADDON_CONTEXT* context, int argc, sqlite3_value** argv);

AR_AO_EXPORTED int ar_addon_init(AR_ADDON_CONTEXT* context)
{
	AR_AO_TRANSFORMATION_DEF* transdef = NULL;

	AR_AO_INIT(context);

	transdef = GET_AR_AO_TRANSFORMATION_DEF();
	transdef->displayName = "encrypt_aes(X)";
	transdef->functionName = "encrypt_aes";
	transdef->description = "encrypt data with AES-256";
	transdef->func = encrypt_aes;
	transdef->nArgs = 1;
	AR_AO_REGISRATION->register_user_defined_transformation(transdef);
	
	// key with pool memory - Get key from azure key vault and save to addon pool memory
	AR_AO_LOG->log_trace("started generate key from azure key vault");
	char* key = auth_plt_gen_key();
	AR_AO_MEM->set_ctx(context->addonPool, poolKeyName, key, NULL);
	AR_AO_MEM->set_ctx(context->addonPool, poolKeyVersionName, keyVersion, NULL);
	AR_AO_MEM->set_ctx(context->addonPool, poolKeyIdName, (char*)keyId, NULL);
	AR_AO_LOG->log_trace(keyVersion);
	AR_AO_LOG->log_trace(keyId);
	AR_AO_LOG->log_trace("key vault has been saved to addno pool memory");
	//
	return 0;
}

static void encrypt_aes(AR_ADDON_CONTEXT* context, int argc, sqlite3_value** argv)
{
	AR_AO_LOG->log_trace("enter encrypt_aes");
	if (argc >= 1)
	{
		char* param = "";
		char* paramTmp = "";
		param = (char*)AR_AO_SQLITE->sqlite3_value_text(argv[0]);
		char aes_input[1024] = "";

		

		char* resText = "";

		if (param == NULL || strlen(param) == 0) {
			AR_AO_SQLITE->sqlite3_result_text(context, "", -1, SQLITE_TRANSIENT);
		}
		else {
			// Get key vault from addon pool memory
			char* keyctx = "";
			
			// key with pool memory
			AR_AO_MEM->get_ctx(AR_AO_CONTEXT->addonPool, poolKeyName, (void*)&keyctx);
			AR_AO_MEM->get_ctx(AR_AO_CONTEXT->addonPool, poolKeyVersionName, (void*)&keyVersion);
			AR_AO_MEM->get_ctx(AR_AO_CONTEXT->addonPool, poolKeyIdName, (void*)&keyId);
			if (keyctx == "") {
				keyctx = auth_plt_gen_key();
				AR_AO_MEM->set_ctx(context->addonPool, poolKeyName, keyctx, NULL);
				AR_AO_MEM->set_ctx(context->addonPool, poolKeyVersionName, keyVersion, NULL);
				AR_AO_MEM->set_ctx(context->addonPool, poolKeyIdName, keyId, NULL);
			}
			//
			
			// key without pool memory - always retrieve new
			/*keyctx = auth_plt_gen_key(); */
			//
			
			// Unused - get plain text as key from kv
			//char aes_key[32] = "";
			//strcpy((const char*)aes_key, keyctx);

			unsigned char aes_key[32];
			// Get base64 from kv and decode key to byte[32]
			size_t decode_size = strlen(keyctx);
			unsigned char* aes_key_de = base64_decode(keyctx, decode_size, &decode_size);
			memcpy(aes_key, aes_key_de, 32);
			//

			char iv[AES_BLOCK_SIZE];
			char* ran = generateRandomString(16);
			memcpy(iv, ran, AES_BLOCK_SIZE);

			long ivSize = 16;
			char* ivBase64 = base64_encode(ran, ivSize, &ivSize);

			paramTmp = concatenate(param, " ", "");

			strcpy((char*)aes_input, (char*)paramTmp);

			char enc_out[AES_BLOCK_SIZE * ((sizeof(aes_input) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE)];
			char dec_out[sizeof(aes_input)];

			strcpy((char*)aes_input, (char*)param);

			AES_KEY enc_key, dec_key;
			AES_set_encrypt_key(aes_key, sizeof(aes_key) * 8, &enc_key);
			AES_cbc_encrypt(aes_input, enc_out, strlen(param) + 1, &enc_key, iv, AES_ENCRYPT);

			long input_size = AES_BLOCK_SIZE * ((strlen(param) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE);
			char* encoded_data = base64_encode(enc_out, input_size, &input_size);

			memset(param, 0x00, sizeof(param));
			memset(paramTmp, 0x00, sizeof(paramTmp));

			

			resText = concatenate("{ \"keyId\": \"", keyId, "\", \"version\": \"");
			resText = concatenate(resText, strrchr(keyVersion, '/') + 1, "\", \"cipherText\": \"");
			resText = concatenate(resText, encoded_data, "\", \"iv\": \"");
			resText = concatenate(resText, ivBase64, "\" }");

			//memset(ran, 0x00, sizeof(ran));
			/*memset(iv, 0x00, AES_BLOCK_SIZE);*/

			AR_AO_SQLITE->sqlite3_result_text(context, resText, -1, SQLITE_TRANSIENT);

			//AR_AO_SQLITE->sqlite3_result_text(context, encoded_data, -1, SQLITE_TRANSIENT);
		}

		memset(aes_input, 0x00, 1024);
		

		AR_AO_LOG->log_trace("Before %s", "return");
	}
	else
	{
		AR_AO_SQLITE->sqlite3_result_error(context, "Not enough parameters", SQLITE_ERROR);
	}

	AR_AO_LOG->log_trace("leave encrypt_aes");
}
