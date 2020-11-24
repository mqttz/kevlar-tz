/*
 * Parts of the following program is based on a software with the following
 * notices:
 *
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>
#include <tee_tcpsocket.h>
#include <__tee_tcpsocket_defines_extensions.h>

#include <mqttz_ta.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* TODO check for MQTTZ_ID correctness */

/* Cache module {{{
 *
 * The code in this section implements a cache (with policy LRU or FIFO) with
 * data that never changes (once a block has been stored with an ID, it can't be
 * changed, unless using a new ID).
 *
 * The cache assumes all entries have the same size (TA_MQTTZ_AES_KEY_SZ) and
 * the IDs are a 0-padded number of TA_MQTTZ_ID_SZ digits (doesn't need to be a
 * null-terminating string). The function to access the cache are the following:
 *
 *     static Cache * init_cache(int max_size, int hash_size, int policy)
 *     char * cache_query(Cache *cache, char *id)
 *     TEE_Result cache_save_object(Cache *cache, char *id, char *data)
 *
 * Which initialize the cache, return a copy of a value previously stored and
 * save a new object, respectively.
 */

typedef struct Node {
	char *id;
	char *data;
	struct Node *next_queue;
	struct Node *prev_queue;
	struct Node *next_hash;
	struct Node *prev_hash;
} Node;

typedef struct Cache {
	Node **elems;
	Node *first;
	Node *last;
	int max_size;
	int size;
	int id_sz;
	int data_sz;
	int policy;
	int hash_size;
} Cache;

/* Simplified atoi function. Only accepts unsigned integers and doesn't check
 * for incorrect input */
int atoi(const char *str)
{
	int res = 0;
	for (int i = 0; str[i] != '\0'; ++i)
		res = res * 10 + str[i] - '0';
	return res;
}

/* Read data from secure storage. */
TEE_Result read_ss(const char *id, char *data, uint32_t *data_sz)
{
	TEE_ObjectHandle object;
	TEE_ObjectInfo object_info;
	TEE_Result res;

	/* check if object is in memory */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, id, strlen(id),
	                               TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ,
	                               &object);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open persistent object, res=0x%08x", res);
		return res;
	}

	res = TEE_GetObjectInfo1(object, &object_info);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to create persistent object, res=0x%08x", res);
		TEE_CloseObject(object);
		return res;
	}
	if (object_info.dataSize > *data_sz) {   /* buffer too short */
		EMSG("Reading buffer too short. Minimum size: %d",
		     object_info.dataSize);
		TEE_CloseObject(object);
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = TEE_ReadObjectData(object, data, object_info.dataSize, data_sz);
	if (res != TEE_SUCCESS || *data_sz != object_info.dataSize) {
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
		     res, *data_sz, object_info.dataSize);
	}

	TEE_CloseObject(object);
	return res;
}

/* Write data to secure storage. */
TEE_Result write_ss(const char *id, const char *data, uint32_t data_sz)
{
	TEE_ObjectHandle object;
	TEE_Result res;
	uint32_t obj_data_flag = TEE_DATA_FLAG_ACCESS_READ | /* read object */
	        TEE_DATA_FLAG_ACCESS_WRITE |        /* write object */
	        TEE_DATA_FLAG_ACCESS_WRITE_META |   /* delete/rename object*/
	        TEE_DATA_FLAG_OVERWRITE;            /* delete object with same ID */

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, id, strlen(id),
	        obj_data_flag, TEE_HANDLE_NULL, NULL, 0, &object);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
		return res;
	}

	res = TEE_WriteObjectData(object, data, data_sz);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_WriteObjectData failed 0x%08x", res);
		TEE_CloseAndDeletePersistentObject1(object);
		return res;
	}

	TEE_CloseObject(object);
	return res;
}

int cache_hash(const char *str, int len)
{
	char s[len+1];
	TEE_MemMove(s, str, len);
	s[len] = '\0';
	return atoi(s) % TA_CACHE_HASH_SZ;
}

static Node * init_node(Cache *cache, const char *id, const char *data)
{
	Node *node = (Node *) TEE_Malloc(sizeof(Node), 0);
	node->id = (char *) TEE_Malloc(sizeof(char) * cache->id_sz, 0);
	TEE_MemMove(node->id, id, cache->id_sz);
	node->data = (char *) TEE_Malloc(sizeof(char) * cache->data_sz, 0);
	TEE_MemMove(node->data, data, cache->data_sz);
	node->next_queue = NULL;
	node->prev_queue = NULL;
	node->next_hash = NULL;
	node->prev_hash = NULL;
	return node;
}

void free_node(Node *node)
{
	TEE_Free((void *) node->id);
	TEE_Free((void *) node->data);
	TEE_Free((void *) node); 
	return;
}

Cache * init_cache(int max_size, int hash_size, int id_sz, int data_sz, int policy)
{
	int i;

	Cache *cache = (Cache *) TEE_Malloc(sizeof(Cache), 0);
	cache->max_size = max_size;
	cache->hash_size = hash_size;
	cache->data_sz = data_sz;
	cache->id_sz = id_sz;
	cache->policy = policy;

	cache->size = 0;
	cache->first = NULL;
	cache->last = NULL;
	cache->elems = (Node **) TEE_Malloc(sizeof(Node *) * hash_size, 0);
	for (i = 0; i < hash_size; i++)
		cache->elems[i] = NULL;

	return cache;
}

void free_cache(Cache *cache)
{
	Node *current = cache->first;
	while (current != NULL) {
		Node *next = current->next_queue;
		free_node(current);
		current = next;
	}
	TEE_Free((void *) cache->elems);
	TEE_Free((void *) cache);
	return;
}

/* Delete an element of the cache (LRU or FIFO policy only). */
void cache_pop(Cache *cache)
{
	if (cache->size == 0)
		return;

	Node *old_last = cache->last;

	/* update hashtable */
	if (old_last->next_hash != NULL)
		old_last->next_hash->prev_hash = old_last->prev_hash;
	if (old_last->prev_hash == NULL)
		cache->elems[cache_hash(old_last->id, cache->id_sz)] = old_last->next_hash;
	else
		old_last->prev_hash->next_hash = old_last->next_hash;

	/* update LRU/FIFO queue */
	cache->last = old_last->prev_queue;
	if (cache->last != NULL)
		cache->last->next_queue = NULL;
	else
		cache->first = NULL;

	free_node(old_last);
	cache->size -= 1;
	return;
}

/* Add new element to cache. Deletes one if full. */
void cache_add(Cache *cache, const char *id, const char *data)
{
	int i;

	if (cache->size == cache->max_size)
		cache_pop(cache);

	Node *node = init_node(cache, id, data);

	/* update hashtable */
	i = cache_hash(id, cache->id_sz);
	if (cache->elems[i] != NULL) {
		cache->elems[i]->prev_hash = node;
		node->next_hash = cache->elems[i];
	}
	cache->elems[i] = node;

	/* update LRU/FIFO queue */
	if (cache->first != NULL) {
		cache->first->prev_queue = node;
		node->next_queue = cache->first;
	} else {
		cache->last = node;
	}
	cache->first = node;

	cache->size += 1;
	return;
}

/* Set element of cache as most recently used (for LRU policy). */
void cache_to_front(Cache *cache, Node *node)
{
	if (cache->first == node)
		return;

	if (cache->last == node)
		cache->last = node->prev_queue;
	else
		node->next_queue->prev_queue = node->prev_queue;

	node->prev_queue->next_queue = node->next_queue;
	node->prev_queue = NULL;
	node->next_queue = cache->first;
	cache->first->prev_queue = node;
	cache->first = node;

	return;
}

/* Query an element by ID. Will retrieve from memory if not found. */
char * cache_query(Cache *cache, const char *id)
{
	char *data;

	/* look for node in hashtable */
	Node *node = cache->elems[cache_hash(id, cache->id_sz)];
	while (node != NULL && TEE_MemCompare(id, node->id, cache->id_sz)) {
		node = node->next_hash;
	}

	data = (char *)TEE_Malloc(sizeof(char) * cache->data_sz, 0);
	if (node == NULL) {     /* cache miss */
		uint32_t data_sz = cache->data_sz;
		if (read_ss(id, data, &data_sz) != TEE_SUCCESS) {
			EMSG("ID not found in storage");
			return NULL;
		}
		cache_add(cache, id, data);
	} else {                /* cache hit */
		if (cache->policy == TA_CACHE_POLICY_LRU)
			cache_to_front(cache, node);
		TEE_MemMove(data, node->data, cache->data_sz);
	}

	return data;
}

/* Save new key to secure storage. data size must be cache->data_sz. */
TEE_Result cache_save_object(Cache *cache, const char *id, const char *data)
{
	return write_ss(id, data, cache->data_sz);
}

/* End of cache module }}} */

/* AES encryption and decryption module {{{ */

typedef struct AES_Cipher {
	uint32_t algo;
	uint32_t mode;
	uint32_t key_size;
	TEE_OperationHandle op_handle;
	TEE_ObjectHandle key_handle;
} AES_Cipher;

TEE_Result alloc_resources(AES_Cipher *aes_c, uint32_t mode, char **dummy_key)
{
	TEE_Attribute attr;
	TEE_Result res;

	aes_c->algo = TEE_ALG_AES_CBC_NOPAD;
	aes_c->key_size = TA_MQTTZ_AES_KEY_SZ;

	if (mode != TEE_MODE_ENCRYPT && mode != TEE_MODE_DECRYPT) {
		EMSG("AES mode not supported: %d.", mode);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	aes_c->mode = mode;

	/* Free previous operation handle */
	if (aes_c->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(aes_c->op_handle);

	/* Allocate operation */
	res = TEE_AllocateOperation(&aes_c->op_handle, aes_c->algo, aes_c->mode,
	                            aes_c->key_size * 8);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_AllocateOperation failed.");
		aes_c->op_handle = TEE_HANDLE_NULL;
		goto err;
	}

	/* Free previous key handle */
	if (aes_c->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(aes_c->key_handle);

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, aes_c->key_size * 8,
	                                  &aes_c->key_handle);

	if (res != TEE_SUCCESS) {
		EMSG("TEE_AllocateTransitionObject failed.");
		aes_c->key_handle = TEE_HANDLE_NULL;
		goto err;
	}

	/* Load Dummy Key */
	/* This array must be freed */
	*dummy_key = TEE_Malloc(aes_c->key_size, 0);
	if (!(*dummy_key)) {
		EMSG("Out of memory.");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, *dummy_key, aes_c->key_size);
	res = TEE_PopulateTransientObject(aes_c->key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed.");
		goto err;
	}

	res = TEE_SetOperationKey(aes_c->op_handle, aes_c->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed.");
		goto err;
	}

	return res;
err:
	if (aes_c->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(aes_c->op_handle);
	aes_c->op_handle = TEE_HANDLE_NULL;
	if (aes_c->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(aes_c->key_handle);
	aes_c->key_handle = TEE_HANDLE_NULL;
	return res;
}

TEE_Result set_aes_key(AES_Cipher *aes_c, const char *key)
{
	TEE_Attribute attr;
	TEE_Result res;

	/* Load key */
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, aes_c->key_size);
	TEE_ResetTransientObject(aes_c->key_handle);
	res = TEE_PopulateTransientObject(aes_c->key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed.");
		return res;
	}

	TEE_ResetOperation(aes_c->op_handle);
	res = TEE_SetOperationKey(aes_c->op_handle, aes_c->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed.");
		return res;
	}

	return res;
}

TEE_Result set_aes_iv(AES_Cipher *aes_c, const char *iv)
{
	TEE_CipherInit(aes_c->op_handle, iv, TA_MQTTZ_AES_IV_SZ);
	return TEE_SUCCESS;
}

/* Prepares call to TEE_CipherUpdate and then calls it. No padding is applied,
 * so you must make sure the input is padded using PKCS padding (and include the
 * padding in the input size). */
TEE_Result cipher_update(AES_Cipher *aes_c, int mode, const char *key,
        const char *iv, const char *in, size_t in_sz, char *out, size_t *out_sz)
{
	char *dummy_key;

	if (alloc_resources(aes_c, mode, &dummy_key) != TEE_SUCCESS) {
		EMSG("alloc_resources failed (mode: %d).", mode);
	return TEE_ERROR_GENERIC;
	}

	if (set_aes_key(aes_c, key) != TEE_SUCCESS) {
		EMSG("set_aes_key failed (mode: %d).", mode);
		return TEE_ERROR_GENERIC;
	}

	TEE_Free(dummy_key);

	if (set_aes_iv(aes_c, iv) != TEE_SUCCESS) {
		EMSG("set_aes_iv failed (mode: %d).", mode);
		return TEE_ERROR_GENERIC;
	}

	if (TEE_CipherUpdate(aes_c->op_handle, in, in_sz, out,
				out_sz) != TEE_SUCCESS) {
		EMSG("TEE_CipherUpdate failed (mode: %d).", mode);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

/* Decrypts input with orig_key and recrypts it with dest_key. iv, cipher and
 * cipher_sz are updated with the new cipher data */
TEE_Result reencrypt(const char *orig_key, const char *dest_key, char *iv,
        char *cipher, int *cipher_sz)
{
	TEE_Result res;
	AES_Cipher *aes_c;
	char *dec_data;
	uint32_t dec_data_sz;

	aes_c = (AES_Cipher *)TEE_Malloc(sizeof(AES_Cipher), 0);

	dec_data_sz = TA_MQTTZ_MAX_MSG_SZ;
	dec_data = (char *)TEE_Malloc(sizeof(char) * dec_data_sz, 0);
	if (!dec_data) {
		EMSG("Out of memory.\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	res = cipher_update(aes_c, TEE_MODE_DECRYPT, orig_key, iv, cipher,
	                    *cipher_sz, dec_data, &dec_data_sz);

	if (res != TEE_SUCCESS) {
		EMSG("Payload decryption failed.");
		return res;
	}

	TEE_GenerateRandom(iv, TA_MQTTZ_AES_IV_SZ);

	*cipher_sz = TA_MQTTZ_MAX_MSG_SZ;
	res = cipher_update(aes_c, TEE_MODE_ENCRYPT, dest_key, iv, dec_data,
	                    dec_data_sz, cipher, cipher_sz);

	if (res != TEE_SUCCESS) {
		EMSG("Payload encryption failed.\n");
		return res;
	}

	TEE_Free(dec_data);
	TEE_Free(aes_c);        /* FIXME does this correctly free the structure? */

	return TEE_SUCCESS;
}

/* End of AES encryption and decryption module }}} */

/* Base64 encode and decode {{{ */

static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const unsigned char dtable[256] = {
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64,  0, 64, 64,
	64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
	64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

/* Encodes the src array in base64 encoding and writes it in out. Returns size
 * of the outputed data. */
int base64_encode(const unsigned char *src, int len, unsigned char *out)
{
	unsigned char *pos;
	const unsigned char *end, *in;

	end = src + len;
	in = src;
	pos = out;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
	}

	*pos = '\0';
	return pos - out;
}

/* Returns the length of the decoded src string (assuming it is correctly
 * encoded using base64 encoding). */
int base64_decode_length(const unsigned char *src)
{
	int len, padding;

	len = strlen((char *)src);
	if (len == 0 || len % 4)
		return 0;

	if (src[len-1] == '=' && src[len-2] == '=')
		padding = 2;
	else if (src[len-1] == '=')
		padding = 1;
	else
		padding = 0;

	return (len / 4) * 3 - padding;
}

/* Decodes the base64 encoded string src and writes it in out. Returns size of
 * the outputed data. */
int base64_decode(const unsigned char *src, int len, unsigned char *out)
{
	unsigned char *pos, block[4], tmp;
	int i, count;
	int pad = 0;

	if (len == 0 || len % 4)
		return -1;

	for (i = 0; i < len; i++) {
		if (dtable[src[i]] == 0x80)
			return -1;
	}

	pos = out;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					return -1;
				}
				break;
			}
		}
	}

	return pos - out;
}

/* End of base64 encode and decode }}} */

/* Replaces first appearence of delim for '\0' and returns the position. If no
 * appearence of the character is found the function return -1. This function
 * substitutes strtok which is not implemented. */
int str_cut_delim(char * str, char delim)
{
	int len;

	for (len = 0; str[len] != '\0' && str[len] != delim; len++);
	if (str[len] == '\0')
		return -1;

	str[len] = '\0';
	return len;
}

/* Parses the input string and writes to the respective values. Assuming the
 * input is for a reencryption call. */
TEE_Result parse_input_reencrypt(char *mess, char *orig_id, char *dest_id,
        char *iv, char *cipher, int *cipher_sz)
{
	size_t tmp_sz;
	char *ptr = mess;
	int delim = str_cut_delim(mess, ' ');

	if (delim == -1) {
		EMSG("Invalid message");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	tmp_sz = strlen(ptr);
	if (tmp_sz != TA_MQTTZ_ID_SZ) {
		EMSG("Origin MQT-TZ ID size is %ld and should be %d.", tmp_sz,
		     TA_MQTTZ_ID_SZ);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	strcpy(orig_id, ptr);

	ptr += delim + 1;
	delim = str_cut_delim(ptr, ' ');
	if (delim == -1) {
		EMSG("Invalid message");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	tmp_sz = strlen(ptr);
	if (tmp_sz != TA_MQTTZ_ID_SZ) {
		EMSG("Destination MQT-TZ ID size is %ld and should be %d.", tmp_sz,
		     TA_MQTTZ_ID_SZ);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	strcpy(dest_id, ptr);

	ptr += delim + 1;
	delim = str_cut_delim(ptr, ' ');
	if (delim == -1) {
		EMSG("Invalid message");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	tmp_sz = base64_decode_length((unsigned char *)ptr);
	if (tmp_sz != TA_MQTTZ_AES_IV_SZ) {
		EMSG("IV length is %ld and should be %d.", tmp_sz,
		     TA_MQTTZ_AES_IV_SZ);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	tmp_sz = base64_decode((unsigned char *)ptr, strlen(ptr),
	                       (unsigned char *)iv);
	if (tmp_sz != TA_MQTTZ_AES_IV_SZ) {
		EMSG("Error decoding base64 IV.");
		return TEE_ERROR_GENERIC;
	}

	ptr += delim + 1;
	*cipher_sz = base64_decode((unsigned char *)ptr, strlen(ptr),
	                           (unsigned char *)cipher);
	if (*cipher_sz < 0) {
		EMSG("Error decoding base64 data.");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

/* Parses the input string and writes to the respective values. Assuming the
 * input is for a new key storage call. */
TEE_Result parse_input_store(char *mess, char *orig_id, char *iv,
        char *cipher, int *cipher_sz)
{
	size_t tmp_sz;
	char *ptr = mess;
	int delim = str_cut_delim(mess, ' ');

	if (delim == -1) {
		EMSG("Invalid message");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	tmp_sz = strlen(ptr);
	if (tmp_sz != TA_MQTTZ_ID_SZ) {
		EMSG("MQT-TZ ID size is %ld and should be %d.", tmp_sz,
		     TA_MQTTZ_ID_SZ);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	strcpy(orig_id, ptr);

	ptr += delim + 1;
	delim = str_cut_delim(ptr, ' ');
	if (delim == -1) {
		EMSG("Invalid message");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	tmp_sz = base64_decode_length(ptr);
	if (tmp_sz != TA_MQTTZ_AES_IV_SZ) {
		EMSG("IV length is %ld and should be %d.", tmp_sz, TA_MQTTZ_AES_IV_SZ);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	tmp_sz = base64_decode((unsigned char *)ptr, strlen(ptr),
	                       (unsigned char *)iv);
	if (tmp_sz != TA_MQTTZ_AES_IV_SZ) {
		EMSG("Error decoding base64 IV.");
		return TEE_ERROR_GENERIC;
	}

	ptr += delim + 1;
	*cipher_sz = base64_decode((unsigned char *)ptr, strlen(ptr),
	                           (unsigned char *)cipher);
	if (*cipher_sz < 0) {
		EMSG("Error decoding base64 data.");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

/* Encodes the encrypted data as MQT-TZ expects it. */
TEE_Result encode_output(char *out, int *out_sz, const char *iv,
        const char *cipher, int *cipher_sz)
{
	unsigned char *e_iv, *e_cipher;
	int tmp;

	e_iv = (unsigned char *)TEE_Malloc(sizeof(char) *
	                                   ((TA_MQTTZ_AES_IV_SZ + 2)/3 * 4 + 1), 0);
	base64_encode((unsigned char *)iv, TA_MQTTZ_AES_IV_SZ, e_iv);

	e_cipher = (unsigned char *)TEE_Malloc(sizeof(char) *
	                                       ((*cipher_sz + 2)/3 * 4 + 1), 0);
	base64_encode((unsigned char *)cipher, *cipher_sz, e_cipher);

	tmp = snprintf(out, *out_sz, "{iv: %s, payload: %s}", e_iv, e_cipher);
	if (tmp >= *out_sz) {
		EMSG("Message truncated. Buffer is too small.");
		free(e_iv);
		free(e_cipher);
		return TEE_ERROR_GENERIC;
	}
	*out_sz = tmp+1;

	free(e_iv);
	free(e_cipher);
	return TEE_SUCCESS;
}

/* Encrypts the MQT-TZ ID of the client. This is used for the response to a new
 * key store call. */
TEE_Result encrypt_id(const char *id, const char *key, char *iv, char *cipher,
        int *cipher_sz)
{
	AES_Cipher *aes_c;
	TEE_Result res;
	char *id_padded;
	int id_padded_sz;

	aes_c = (AES_Cipher *)TEE_Malloc(sizeof(AES_Cipher), 0);
	TEE_GenerateRandom(iv, TA_MQTTZ_AES_IV_SZ);

	/* Make PKCS padding (the default for OpenSSL and the one MQT-TZ expects) */
	id_padded_sz = (TA_MQTTZ_ID_SZ/16 + 1) * 16;
	id_padded = (char *)TEE_Malloc(sizeof(char) * id_padded_sz, 0);
	TEE_MemFill(id_padded, id_padded_sz - TA_MQTTZ_ID_SZ, id_padded_sz);
	TEE_MemMove(id_padded, id, TA_MQTTZ_ID_SZ);

	res = cipher_update(aes_c, TEE_MODE_ENCRYPT, key, iv, id_padded,
	                    id_padded_sz, cipher, cipher_sz);
	if (res != TEE_SUCCESS) {
		EMSG("Payload encryption failed.\n");
		return res;
	}

	TEE_Free(id_padded);
	TEE_Free(aes_c);        /* FIXME does this correctly free the structure? */
	return TEE_SUCCESS;
}

/* Process the request received by TCP. */
TEE_Result process_request(Cache *cache, char *mess, int *len)
{
	char *orig_id, *dest_id, *orig_key, *dest_key, *iv, *cipher;
	int cipher_sz;

	if (strlen(mess)+1 != *len) {
		EMSG("Message length is %ld + 1, but %d bytes were transferred.",
		     strlen(mess), *len);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (*len == 0) {
		EMSG("Message is empty.");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* TODO check the return values for the function call to check for errors */
	if (mess[0] == 'R') {            /* Reencryption */
		orig_id = (char *)TEE_Malloc(sizeof(char) * (TA_MQTTZ_ID_SZ + 1), 0);
		dest_id = (char *)TEE_Malloc(sizeof(char) * (TA_MQTTZ_ID_SZ + 1), 0);
		iv = (char *)TEE_Malloc(sizeof(char) * (TA_MQTTZ_AES_IV_SZ + 1), 0);
		cipher = (char *)TEE_Malloc(sizeof(char) * (TA_MQTTZ_MAX_MSG_SZ + 1), 0);

		/* Parse and decode the input string into the variables it contains */
		parse_input_reencrypt(mess+1, orig_id, dest_id, iv, cipher, &cipher_sz);

		/* Get the keys from the cache */
		orig_key = cache_query(cache, orig_id);
		dest_key = cache_query(cache, dest_id);

		/* Reencrypt the payload with the retreived keys */
		reencrypt(orig_key, dest_key, iv, cipher, &cipher_sz);

		/* Encode output for MQT-TZ broker */
		*len = TA_TCP_MAX_PKG_SZ;
		encode_output(mess, len, iv, cipher, &cipher_sz);

		TEE_Free(orig_id);
		TEE_Free(dest_id);
		TEE_Free(iv);
		TEE_Free(cipher);
	} else if (mess[0] == 'N') {     /* Store new key */
		orig_id = (char *)TEE_Malloc(sizeof(char) * (TA_MQTTZ_ID_SZ + 1), 0);
		iv = (char *)TEE_Malloc(sizeof(char) * (TA_MQTTZ_AES_IV_SZ + 1), 0);
		cipher = (char *)TEE_Malloc(sizeof(char) * (TA_MQTTZ_MAX_MSG_SZ + 1), 0);
		orig_key = (char *)TEE_Malloc(sizeof(char) * (TA_MQTTZ_AES_KEY_SZ + 1), 0);

		parse_input_store(mess+1, orig_id, iv, cipher, &cipher_sz);

		/* Here we should decrypt the cipher, but for now, the key is sent
		 * unencrypted */
		if (cipher_sz != TA_MQTTZ_AES_KEY_SZ) {
			EMSG("Key length is %d and should be %d.", cipher_sz, TA_MQTTZ_AES_KEY_SZ);
			return TEE_ERROR_BAD_PARAMETERS;
		}
		TEE_MemMove(orig_key, cipher, TA_MQTTZ_AES_KEY_SZ);

		/* Save new key */
		cache_save_object(cache, orig_id, orig_key);

		/* Encrypt the ID to return to MQT-TZ */
		cipher_sz = TA_MQTTZ_MAX_MSG_SZ;
		encrypt_id(orig_id, orig_key, iv, cipher, &cipher_sz);
		MSG("cipher_sz: %i", cipher_sz);

		/* Encode output for MQT-TZ broker */
		*len = TA_TCP_MAX_PKG_SZ;
		encode_output(mess, len, iv, cipher, &cipher_sz);

		TEE_Free(orig_id);
		TEE_Free(iv);
		TEE_Free(cipher);
		TEE_Free(orig_key);
	} else {
		EMSG("Malformatted message: First byte must be 'R' or 'N'.");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

/* The main function. It connects to TCP server and calls process_request every
 * time it gets data through TCP. It also sends the response. */
TEE_Result mqttz_ta(void)
{
	TEE_Result res;
	TEE_iSocketHandle sh;
	TEE_iSocket *socket;
	TEE_tcpSocket_Setup setup = { };
	char *mess;
	uint32_t len, error_code;

	Cache *cache = init_cache(TA_CACHE_SZ, TA_CACHE_HASH_SZ, TA_MQTTZ_ID_SZ,
	                          TA_MQTTZ_AES_KEY_SZ, TA_CACHE_POLICY_LRU);

	/* TCP socket set up */
	setup.ipVersion = TEE_IP_VERSION_4;
	setup.server_addr = strndup(TA_TCP_IP, strlen(TA_TCP_IP)+1);
	setup.server_port = TA_TCP_PORT;
	socket = TEE_tcpSocket;

	res = socket->open(&sh, &setup, &error_code);
	if (res != TEE_SUCCESS)
		EMSG("TEE_iSocket->open failed with code 0x%x", res);

	len = TA_TCP_MAX_PKG_SZ;
	mess = TEE_Malloc(sizeof(char) * len, 0);
	if (!mess)
		EMSG("Out of memory.");

	res = TEE_tcpSocket->ioctl(sh, TEE_TCP_SET_RECVBUF, &mess, &len);
	if (res != TEE_SUCCESS)
		EMSG("TEE_iSocket->ioctl failed with code 0x%x", res);

	while (res == TEE_SUCCESS) {
		len = TA_TCP_MAX_PKG_SZ;
		res = socket->recv(sh, mess, &len, TEE_TIMEOUT_INFINITE);
		if (res != TEE_SUCCESS)
			EMSG("TEE_iSocket->recv failed with code 0x%x", res);
		printf("Bytes received: %i, message: %s\n", len, mess);
		process_request(cache, mess, &len);
		printf("Want to send: %s, len: %i\n", mess, len);
		res = socket->send(sh, mess, &len, TEE_TIMEOUT_INFINITE);
		if (res != TEE_SUCCESS)
			EMSG("TEE_iSocket->send failed with code 0x%x", res);
		printf("Bytes sent: %i, message: %s\n", len, mess);
	}

	res = socket->close(sh);

	return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
        TEE_Param __unused params[4], void __unused **session)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *session)
{
	/* Nothing to do */
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session, uint32_t command,
        uint32_t __unused param_types, TEE_Param __unused params[4])
{
	switch (command) {
	case TA_MQTTZ:
		return mqttz_ta();
	default:
		EMSG("Command ID 0x%x is not supported", command);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
