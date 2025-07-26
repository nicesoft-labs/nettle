/* magma.c - GOST R 34.12-2015 (Magma) cipher implementation
 *  Implementation conforms to RFC 8891 test vectors.
 *
 *
 * Copyright: 2017 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "macros.h"
#include "nettle-write.h"
#include "magma.h"

static const uint8_t magma_pi[8][16] = {
  { 12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1 },
  { 6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15 },
  { 11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0 },
  { 12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11 },
  { 7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12 },
  { 5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0 },
  { 8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7 },
  { 1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2 }
};

static uint32_t
magma_f(uint32_t x)
{
  uint32_t y = 0;
  y  = magma_pi[0][(x >>  0) & 0xf];
  y |= magma_pi[1][(x >>  4) & 0xf] << 4;
  y |= magma_pi[2][(x >>  8) & 0xf] << 8;
  y |= magma_pi[3][(x >> 12) & 0xf] << 12;
  y |= magma_pi[4][(x >> 16) & 0xf] << 16;
  y |= magma_pi[5][(x >> 20) & 0xf] << 20;
  y |= magma_pi[6][(x >> 24) & 0xf] << 24;
  y |= magma_pi[7][(x >> 28) & 0xf] << 28;
  return ROTL32(11, y);
}

void
magma_set_key(struct magma_ctx *ctx, const uint8_t *key)
{
  unsigned i;
  for (i = 0; i < 8; i++, key += 4)
    ctx->key[i] = READ_UINT32(key);
}

static void
magma_crypt_block(const struct magma_ctx *ctx, const uint8_t *src, uint8_t *dst, int encrypt)
{
  uint32_t n2 = READ_UINT32(src);
  uint32_t n1 = READ_UINT32(src + 4);
  unsigned i;
  if (encrypt)
    {
      for (i = 0; i < 24; i++)
        {
          uint32_t t = n1;
          n1 = n2 ^ magma_f(n1 + ctx->key[i & 7]);
          n2 = t;
        }
      for (i = 0; i < 8; i++)
        {
          uint32_t t = n1;
          n1 = n2 ^ magma_f(n1 + ctx->key[7 - i]);
          n2 = t;
        }
    }
  else
    {
      for (i = 0; i < 8; i++)
        {
          uint32_t t = n1;
          n1 = n2 ^ magma_f(n1 + ctx->key[i]);
          n2 = t;
        }
      for (i = 0; i < 24; i++)
        {
          uint32_t t = n1;
          n1 = n2 ^ magma_f(n1 + ctx->key[(7 - i) & 7]);
          n2 = t;
        }
    }
  /* Output uses the post-round swap required by the GOST specification.  */
  WRITE_UINT32(dst, n1);
  WRITE_UINT32(dst + 4, n2);
}

void
magma_encrypt(const struct magma_ctx *ctx,
              size_t length, uint8_t *dst,
              const uint8_t *src)
{
  assert(!(length % MAGMA_BLOCK_SIZE));
  while (length)
    {
      magma_crypt_block(ctx, src, dst, 1);
      src += MAGMA_BLOCK_SIZE;
      dst += MAGMA_BLOCK_SIZE;
      length -= MAGMA_BLOCK_SIZE;
    }
}

void
magma_decrypt(const struct magma_ctx *ctx,
              size_t length, uint8_t *dst,
              const uint8_t *src)
{
  assert(!(length % MAGMA_BLOCK_SIZE));
  while (length)
    {
      magma_crypt_block(ctx, src, dst, 0);
      src += MAGMA_BLOCK_SIZE;
      dst += MAGMA_BLOCK_SIZE;
      length -= MAGMA_BLOCK_SIZE;
    }
}
