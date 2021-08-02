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


static void encrypt_aes(sqlite3_context *context, int argc, sqlite3_value **argv);

AR_AO_EXPORTED int ar_addon_init(AR_ADDON_CONTEXT *context)
{
	AR_AO_TRANSFORMATION_DEF *transdef = NULL;
	
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

/* decodeblock - decode 4 '6-bit' characters into 3 8-bit binary bytes */
void decodeblock(unsigned char in[], char* clrstr) {
    unsigned char out[4];
    out[0] = in[0] << 2 | in[1] >> 4;
    out[1] = in[1] << 4 | in[2] >> 2;
    out[2] = in[2] << 6 | in[3] >> 0;
    out[3] = '\0';
    strncat(clrstr, out, sizeof(out));
}

void b64_decode(char* b64src, char* clrdst) {
    int c, phase, i;
    unsigned char in[4];
    char* p;

    clrdst[0] = '\0';
    phase = 0; i = 0;
    while (b64src[i]) {
        c = (int)b64src[i];
        if (c == '=') {
            decodeblock(in, clrdst);
            break;
        }
        p = strchr(encoding_table, c);
        if (p) {
            in[phase] = p - encoding_table;
            phase = (phase + 1) % 4;
            if (phase == 0) {
                decodeblock(in, clrdst);
                in[0] = in[1] = in[2] = in[3] = 0;
            }
        }
        i++;
    }
}

/* encodeblock - encode 3 8-bit binary bytes as 4 '6-bit' characters */
void encodeblock(unsigned char in[], char b64str[], int len) {
    unsigned char out[5];
    out[0] = encoding_table[in[0] >> 2];
    out[1] = encoding_table[((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)];
    out[2] = (unsigned char)(len > 1 ? encoding_table[((in[1] & 0x0f) << 2) |
        ((in[2] & 0xc0) >> 6)] : '=');
    out[3] = (unsigned char)(len > 2 ? encoding_table[in[2] & 0x3f] : '=');
    out[4] = '\0';
    strncat(b64str, out, sizeof(out));
}

/* encode - base64 encode a stream, adding padding if needed */
void b64_encode(unsigned char* clrstr, char* b64dst) {
    unsigned char in[3];
    int i, len = 0;
    int j = 0;

    b64dst[0] = '\0';
    while (clrstr[j]) {
        len = 0;
        for (i = 0; i < 3; i++) {
            in[i] = (unsigned char)clrstr[j];
            if (clrstr[j]) {
                len++; j++;
            }
            else in[i] = 0;
        }
        if (len) {
            encodeblock(in, b64dst, len);
        }
    }
}

const static unsigned char aes_key[32] = "!A%D*G-KaPdRgUkXp2s5v8y/B?E(H+Mb";

static void encrypt_aes(sqlite3_context *context, int argc, sqlite3_value **argv)
{
	AR_AO_LOG->log_trace("enter encrypt_aes");
	if (argc >= 1)
	{
        unsigned char iv[AES_BLOCK_SIZE] = "0000000000000000";
        unsigned char ivde[AES_BLOCK_SIZE] = "0000000000000000";

        char* param = (char*)AR_AO_SQLITE->sqlite3_value_text(argv[0]);

        unsigned char aes_input[1024] = "";
        strcpy((const char*)aes_input, param);


        unsigned char enc_out[AES_BLOCK_SIZE * ((sizeof(aes_input) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE)];
        unsigned char dec_out[sizeof(aes_input)];

        printf("Original data: \n[%s]\n\n", aes_input);

        AES_KEY enc_key, dec_key;
        AES_set_encrypt_key(aes_key, sizeof(aes_key) * 8, &enc_key);
        AES_cbc_encrypt(aes_input, enc_out, strlen(param), &enc_key, iv, AES_ENCRYPT);

        //printf("Encrypted data: \n[%s]\n\n", enc_out);

        long input_size = AES_BLOCK_SIZE * ((strlen(param) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE); //sizeof(enc_out);
        char* encoded_data = base64_encode(enc_out, input_size, &input_size);


        //memset(iv, 0x00, AES_BLOCK_SIZE);
      /*  AES_set_decrypt_key(aes_key, sizeof(aes_key) * 8, &dec_key);
        AES_cbc_encrypt(enc_out, dec_out, sizeof(aes_input), &dec_key, ivde, AES_DECRYPT);

        printf("Decrypted data: \n[%s]\n\n", dec_out);*/


		AR_AO_SQLITE->sqlite3_result_text(context, encoded_data, -1, SQLITE_TRANSIENT);
		AR_AO_LOG->log_trace("Before %s", "return");
	}
	else
	{
		AR_AO_SQLITE->sqlite3_result_error(context, "Not enough parameters", SQLITE_ERROR);
	}
	
	AR_AO_LOG->log_trace("leave encrypt_aes");
}
