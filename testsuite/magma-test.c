#include "testutils.h"
#include "magma.h"
#include "cfb.h"

void
test_main(void)
{
  test_cipher(&nettle_magma,
              SHEX("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
              SHEX("92def06b3c130a59 db54c704f8189d20 4a98fb2e67a8024c 8912409b17b57e41"),
              SHEX("9c12d89119ddf784 9add530de023ebe3 23f0c6d3028c8e97 7575524b7759c0c8"));

  test_cipher(&nettle_magma,
              SHEX("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
              SHEX("fedcba9876543210"),
              SHEX("427b2217994b1cae"));

  test_cipher(&nettle_magma,
              SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
              SHEX("1234567800000000"),
              SHEX("d7275c33034bd125"));

  test_cipher(&nettle_magma,
              SHEX("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
              SHEX("1234567800000001"),
              SHEX("a2c12b94283a8bdf"));

  test_cipher(&nettle_magma,
              SHEX("863ea017842c3d372b18a85a28e2317d74befc107720de0c9e8ab974abd00ca0"),
              SHEX("1234567800000002"),
              SHEX("765da5492220533a"));

  test_cipher(&nettle_magma,
              SHEX("863ea017842c3d372b18a85a28e2317d74befc107720de0c9e8ab974abd00ca0"),
              SHEX("1234567800000003"),
              SHEX("efa0b00a19c58828"));

  test_cipher(&nettle_magma,
              SHEX("49a5e2677de555982b8ad5e826652d17eec847bf5b3997a81cf7fe7f1187bd27"),
              SHEX("1234567800000004"),
              SHEX("76017393126d3678"));

  test_cipher(&nettle_magma,
              SHEX("49a5e2677de555982b8ad5e826652d17eec847bf5b3997a81cf7fe7f1187bd27"),
              SHEX("1234567800000005"),
              SHEX("c7139c5ff062d625"));

  test_cipher(&nettle_magma,
              SHEX("3256bf3f97b5667426a9fb1c5eaabe41893ccdd5a868f9b63b0aa90720fa43c4"),
              SHEX("1234567800000006"),
              SHEX("063962bf43c8773e"));
}
