#include <string.h>
#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

#include "util.h"
#include "hash.h"
#include "crypt.h"

#define LGPFX "CRYPT:"


/*
 *---------------------------------------------------------------------
 *
 * secure_alloc --
 *
 *---------------------------------------------------------------------
 */

struct secure_area*
secure_alloc(size_t len)
{
   struct secure_area *area;
   size_t alloc_len;
   bool s;

   alloc_len = sizeof *area + len;
   area = safe_calloc(1, alloc_len);
   area->len       = len;
   area->alloc_len = alloc_len;

   s = util_memlock(area, alloc_len);
   if (s == 1) {
      return area;
   }
   free(area);

   return NULL;
}


/*
 *---------------------------------------------------------------------
 *
 * secure_free --
 *
 *---------------------------------------------------------------------
 */

void
secure_free(struct secure_area *area)
{
   size_t len;

   if (area == NULL) {
      return;
   }

   /*
    * First clean, and only then munlock().
    */
   len = area->alloc_len;
   OPENSSL_cleanse(area, len);
   util_memunlock(area, len);
   free(area);
}


/*
 *---------------------------------------------------------------------
 *
 * crypt_determine_count --
 *
 *---------------------------------------------------------------------
 */

static int
crypt_determine_count(const struct secure_area *pass,
                      struct crypt_key         *ckey)
{
   int64 count;
   int loop;

   count = CRYPT_NUM_ITERATIONS_OLD;
   loop = 3;

   while (loop > 0) {
      mtime_t ts;
      int len;

      ts = time_get();
      len = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), ckey->salt,
                           pass->buf, pass->len, count, ckey->key, ckey->iv);

      if (len != sizeof ckey->key) {
         OPENSSL_cleanse(ckey->key, sizeof ckey->key);
         OPENSSL_cleanse(ckey->iv,  sizeof ckey->iv);
         return -1;
      }
      ts = time_get() - ts;
      ASSERT(ts > 0);
      count = count * 100 * 1000 * 1.0 / ts;
      loop--;
   }

   Log(LGPFX" %s: result= %llu\n", __FUNCTION__, count);

   return MAX(CRYPT_NUM_ITERATIONS_MIN, count);
}


/*
 *---------------------------------------------------------------------
 *
 * crypt_set_key_from_passphrase --
 *
 *---------------------------------------------------------------------
 */

bool
crypt_set_key_from_passphrase(const struct secure_area *pass,
                              struct crypt_key         *ckey,
                              int64                    *count_ptr)
{
   int count;
   int len;

   ASSERT(count_ptr);

   count = *count_ptr;
   if (*count_ptr == 0) {
      count = crypt_determine_count(pass, ckey);
      if (count < 0) {
         return 0;
      }
   }

   len = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), ckey->salt,
                        pass->buf, pass->len, count, ckey->key, ckey->iv);

   if (len != sizeof ckey->key) {
      OPENSSL_cleanse(ckey->key, sizeof ckey->key);
      OPENSSL_cleanse(ckey->iv,  sizeof ckey->iv);
      return 0;
   }

   if (*count_ptr == 0) {
      *count_ptr = count;
   }

   return 1;
}


/*
 *---------------------------------------------------------------------
 *
 * crypt_encrypt --
 *
 *---------------------------------------------------------------------
 */

bool
crypt_encrypt(struct crypt_key         *ckey,
              const struct secure_area *plaintext,
              uint8                   **cipher,
              size_t                   *cipher_len)
{
   EVP_CIPHER_CTX ctx;
   int clen;
   int flen;
   uint8 *c;
   int res;

   Log(LGPFX" %s:%u\n", __FUNCTION__, __LINE__);

   *cipher = NULL;
   *cipher_len = 0;
   clen = 0;
   flen = 0;
   clen = plaintext->len + AES_BLOCK_SIZE;

   c = safe_malloc(clen);

   EVP_CIPHER_CTX_init(&ctx);

   res = EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, ckey->key, ckey->iv);
   res = res && EVP_EncryptUpdate(&ctx, c, &clen, plaintext->buf, plaintext->len);
   res = res && EVP_EncryptFinal_ex(&ctx, c + clen, &flen);

   EVP_CIPHER_CTX_cleanup(&ctx);

   if (res == 0) {
      Log(LGPFX" %s: failed to encrypt %zu bytes\n",
          __FUNCTION__, plaintext->len);
      OPENSSL_cleanse(c, clen);
      free(c);
      return 0;
   }

   *cipher = c;
   *cipher_len = clen + flen;

   return 1;
}


/*
 *---------------------------------------------------------------------
 *
 * crypt_decrypt --
 *
 *---------------------------------------------------------------------
 */

bool
crypt_decrypt(struct crypt_key    *ckey,
              const uint8         *cipher,
              size_t               cipher_len,
              struct secure_area **plaintext)
{
   struct secure_area *sec;
   EVP_CIPHER_CTX ctx;
   int dlen;
   int flen;
   int res;

   *plaintext = NULL;
   dlen = cipher_len;
   flen = 0;

   sec = secure_alloc(dlen);

   EVP_CIPHER_CTX_init(&ctx);

   res = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, ckey->key, ckey->iv);
   res = res && EVP_DecryptUpdate(&ctx, sec->buf, &dlen, cipher, cipher_len);
   res = res && EVP_DecryptFinal_ex(&ctx, sec->buf + dlen, &flen);

   EVP_CIPHER_CTX_cleanup(&ctx);

   if (res == 0) {
      Log(LGPFX" %s: failed to decrypt %zu bytes\n", __FUNCTION__, cipher_len);
      secure_free(sec);
      return 0;
   }

   sec->len = dlen + flen;
   *plaintext = sec;

   return 1;
}



/*
 *---------------------------------------------------------------------
 *
 * crypt_hmac_sha256 --
 *
 *---------------------------------------------------------------------
 */

void
crypt_hmac_sha256(const void  *text,
                  size_t       text_len,
                  const uint8 *key,
                  size_t       key_len,
                  uint256     *digest)
{
    uint8 buffer[1024];
    uint256 key_hash;
    uint256 buf_hash;
    uint8 ipad[65];
    uint8 opad[65];
    size_t i;

    ASSERT(text_len < 512);

    uint256_zero_out(&key_hash);

    if (key_len > 64) {
       sha256_calc(key, key_len, &key_hash);
       key_len = sizeof(key_hash);
       key = key_hash.data;
    }
    ASSERT(key_len < sizeof ipad);
    ASSERT(key_len < sizeof opad);

    memset(ipad, 0, sizeof ipad);
    memset(opad, 0, sizeof opad);

    memcpy(ipad, key, key_len);
    memcpy(opad, key, key_len);

    for (i = 0; i < 64; i++ ) {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
    }

    memcpy(buffer, ipad, 64);
    memcpy(buffer + 64, text, text_len);

    sha256_calc(buffer, 64 + text_len, &buf_hash);

    memcpy(buffer, opad, 64);
    memcpy(buffer + 64, &buf_hash, sizeof buf_hash);

    sha256_calc(buffer, 64 + sizeof buf_hash, digest);
}

/*
 *---------------------------------------------------------------------
 *
 * crypt_hmac_sha512 --
 *
 *---------------------------------------------------------------------
 */

void
crypt_hmac_sha512(const void  *text,
                  size_t       text_len,
                  const uint8 *key,
                  size_t       key_len,
                  uint512     *digest)
{
    uint8 buffer[1024];
    uint512 key_hash;
    uint512 buf_hash;
    uint8 ipad[129];
    uint8 opad[129];
    size_t i;

    ASSERT(text_len < 512);

    uint512_zero_out(&key_hash);

    if (key_len > 128) {
       sha512_calc(key, key_len, &key_hash);
       key_len = sizeof(key_hash);
       key = key_hash.data;
    }
    ASSERT(key_len < sizeof ipad);
    ASSERT(key_len < sizeof opad);

    memset(ipad, 0, sizeof ipad);
    memset(opad, 0, sizeof opad);

    memcpy(ipad, key, key_len);
    memcpy(opad, key, key_len);

    for (i = 0; i < 128; i++ ) {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
    }

    memcpy(buffer, ipad, 128);
    memcpy(buffer + 128, text, text_len);

    sha512_calc(buffer, 128 + text_len, &buf_hash);

    memcpy(buffer, opad, 128);
    memcpy(buffer + 128, &buf_hash, sizeof buf_hash);

    sha512_calc(buffer, 128 + sizeof buf_hash, digest);
}


struct hmac512vec {
	char *key;
	char *text;
	char *result;
} hmac512_testvectors[] = {
	{
		.key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		.text = "4869205468657265",
		.result = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
	}, {
		.key = "4a656665",
		.text = "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
		.result = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
	}, {
		.key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		.text = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		.result = "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
	}, {
		.key = "0102030405060708090a0b0c0d0e0f10111213141516171819",
		.text = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
		.result = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
	}, {
		.key = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
		.text = "546573742057697468205472756e636174696f6e",
		.result = "415fad6271580a531d4179bc891d87a6",
	}, {
		.key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		.text = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
		.result = "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
	}, {
		.key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		.text = "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
			"68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365"
			"642062792074686520484d414320616c676f726974686d2e",
		.result = "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
	}
};

void test_hmac512(void)
{
	struct hmac512vec *v;
	char key[1000];
	char text[1000];
	char out[129];
	uint512 digest;

	for (v = hmac512_testvectors;
		v < hmac512_testvectors + ARRAYSIZE(hmac512_testvectors); v++) {
		int key_len = strlen(v->key) / 2;
		int text_len = strlen(v->text) / 2;

		ASSERT(byte_array_from_str(v->key, key, key_len) == 1);
		ASSERT(byte_array_from_str(v->text, text, text_len) == 1);

		crypt_hmac_sha512((void*)&text, text_len, (void *)&key,
				key_len, &digest);
		uint512_snprintf_reverse((char *)&out, sizeof out, &digest);
		ASSERT(!strncmp(v->result, out, strlen(v->result)));
		printf("wanted:\n%s\ngot:\n%s\n", v->result, out);
	}
}
