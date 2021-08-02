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


static void encrypt_aes(sqlite3_context* context, int argc, sqlite3_value** argv);

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

	return 0;
}


static void encrypt_aes(sqlite3_context* context, int argc, sqlite3_value** argv)
{
	AR_AO_LOG->log_trace("enter encrypt_aes");
	if (argc >= 1)
	{
		unsigned char iv[AES_BLOCK_SIZE] = "0000000000000000";
		unsigned char ivde[AES_BLOCK_SIZE] = "0000000000000000";



		/*char *pszText = (char *)AR_AO_SQLITE->sqlite3_value_text(argv[0]);
		char *pszPrefix = (char *)AR_AO_SQLITE->sqlite3_value_text(argv[1]);
		char pRes[256] = {0};

		snprintf(pRes, 256, "%s_%s", pszPrefix, pszText);*/
		/*  char* param = (char*)"My name is Inteltion, My name is ong 1234567890 asdaerwqefwdfvsdfas";
		  size_t paramSize = strlen(param);

		  char aes_input[1024] = "";
		  strcpy(aes_input, param);*/


		unsigned char aes_input[] = "My name is Inteltion, My name is ong 1234567890 asdaerwqefwdfvsdfas";
		unsigned char enc_out[AES_BLOCK_SIZE * ((sizeof(aes_input) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE)];
		unsigned char dec_out[sizeof(aes_input)];

		printf("Original data: \n[%s]\n\n", aes_input);

		AES_KEY enc_key, dec_key;
		AES_set_encrypt_key(aes_key, sizeof(aes_key) * 8, &enc_key);
		AES_cbc_encrypt(aes_input, enc_out, sizeof(aes_input), &enc_key, iv, AES_ENCRYPT);

		//printf("Encrypted data: \n[%s]\n\n", enc_out);

		long input_size = sizeof(enc_out);
		char* encoded_data = base64_encode(enc_out, input_size, &input_size);

		char mysrc[] = { '\0' };
		strcpy(mysrc, enc_out);
		char myb64[1024] = "";
		b64_encode(mysrc, myb64);

		printf("Encrypted base64 data: \n[%s]\n\n", myb64);

		//memset(iv, 0x00, AES_BLOCK_SIZE);
	  /*  AES_set_decrypt_key(aes_key, sizeof(aes_key) * 8, &dec_key);
		AES_cbc_encrypt(enc_out, dec_out, sizeof(aes_input), &dec_key, ivde, AES_DECRYPT);

		printf("Decrypted data: \n[%s]\n\n", dec_out);*/


		AR_AO_SQLITE->sqlite3_result_text(context, myb64, -1, SQLITE_TRANSIENT);
		AR_AO_LOG->log_trace("Before %s", "return");
	}
	else
	{
		AR_AO_SQLITE->sqlite3_result_error(context, "Not enough parameters", SQLITE_ERROR);
	}

	AR_AO_LOG->log_trace("leave encrypt_aes");
}
