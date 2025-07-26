#include "testutils.h"
#include "magma.h"
#include "macros.h"
#include <stdint.h>

/* Test vectors from RFC 8891, Appendix A */
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
t_transform(uint32_t x)
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
  return y;
}

static uint32_t
g_transform(uint32_t k, uint32_t a)
{
  return ROTL32(11, t_transform(a + k));
}

static void
generate_round_keys(const uint8_t *key, uint32_t *rk)
{
  unsigned i;
  for (i = 0; i < 8; i++, key += 4)
    rk[i] = READ_UINT32(key);
  for (i = 0; i < 8; i++)
    rk[i + 8] = rk[i];
  for (i = 0; i < 8; i++)
    rk[i + 16] = rk[i];
  for (i = 0; i < 8; i++)
    rk[i + 24] = rk[7 - i];
}

void
test_main(void)
{
  /* Transformation t examples */
  ASSERT (t_transform(0xfdb97531) == 0x2a196f34);
  ASSERT (t_transform(0x2a196f34) == 0xebd9f03a);
  ASSERT (t_transform(0xebd9f03a) == 0xb039bb3d);
  ASSERT (t_transform(0xb039bb3d) == 0x68695433);

  /* Transformation g examples */
  ASSERT (g_transform(0x87654321, 0xfedcba98) == 0xfdcbc20c);
  ASSERT (g_transform(0xfdcbc20c, 0x87654321) == 0x7e791a4b);
  ASSERT (g_transform(0x7e791a4b, 0xfdcbc20c) == 0xc76549ec);
  ASSERT (g_transform(0xc76549ec, 0x7e791a4b) == 0x9791c849);

  /* Key schedule example */
  {
    static const uint8_t key[32] =
      { 0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
        0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff };
    static const uint32_t expected[32] =
      {
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
        0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
        0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
        0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
        0xfcfdfeff, 0xf8f9fafb, 0xf4f5f6f7, 0xf0f1f2f3,
        0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc
      };
    uint32_t rk[32];
    struct magma_ctx ctx;
    unsigned i;

    generate_round_keys(key, rk);
    for (i = 0; i < 32; i++)
      ASSERT(rk[i] == expected[i]);

    magma_set_key(&ctx, key);
    for (i = 0; i < 8; i++)
      ASSERT(ctx.key[i] == expected[i]);
  }

  test_cipher(&nettle_magma,
              SHEX("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
              SHEX("92def06b3c130a59 db54c704f8189d20 4a98fb2e67a8024c 8912409b17b57e41"),
              SHEX("2b073f0494f372a0 de70e715d3556e48 11d8d9e9eacfbc1e 7c68260996c67efb"));

  test_cipher(&nettle_magma,
              SHEX("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
              SHEX("fedcba9876543210"),
              SHEX("4ee901e5c2d8ca3d"));

  test_cipher(&nettle_magma,
              SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
              SHEX("1234567800000000"),
              SHEX("3b9a2eaabe783bab"));

  test_cipher(&nettle_magma,
              SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
              SHEX("1234567800000001"),
              SHEX("970fd90806c10d62"));

  test_cipher(&nettle_magma,
              SHEX("863ea017842c3d372b18a85a28e2317d74befc107720de0c9e8ab974abd00ca0"),
              SHEX("1234567800000002"),
              SHEX("c73d459c287b3d1c"));

  test_cipher(&nettle_magma,
              SHEX("863ea017842c3d372b18a85a28e2317d74befc107720de0c9e8ab974abd00ca0"),
              SHEX("1234567800000003"),
              SHEX("86361cacbc1f4c24"));

  test_cipher(&nettle_magma,
              SHEX("49a5e2677de555982b8ad5e826652d17eec847bf5b3997a81cf7fe7f1187bd27"),
              SHEX("1234567800000004"),
              SHEX("b08c4250cb8b640a"));

  test_cipher(&nettle_magma,
              SHEX("49a5e2677de555982b8ad5e826652d17eec847bf5b3997a81cf7fe7f1187bd27"),
              SHEX("1234567800000005"),
              SHEX("327edcd4e88de66f"));

  test_cipher(&nettle_magma,
              SHEX("3256bf3f97b5667426a9fb1c5eaabe41893ccdd5a868f9b63b0aa90720fa43c4"),
              SHEX("1234567800000006"),
              SHEX("a691b50e59bdfa58"));
}
