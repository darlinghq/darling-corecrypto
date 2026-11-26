/* KAT and streaming tests for the FIPS 202 SHAKE/XOF implementation used by
 * the post-quantum backends.  See fips202_vectors.h for vector provenance. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fips202.h"
#include "fips202_vectors.h"

static int checks;
static int failures;

static void check(bool ok, const char *what)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    checks++;
    if (!ok) {
        failures++;
    }
}

static bool equal(const uint8_t *got, const uint8_t *expected, size_t n)
{
    return got != NULL && expected != NULL && memcmp(got, expected, n) == 0;
}

static const uint8_t empty[1] = {0};
static const uint8_t abc[3] = {'a', 'b', 'c'};
static const uint8_t seq200[200] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
    96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
    128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
    144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
    160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175,
    176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
    192, 193, 194, 195, 196, 197, 198, 199,
};

struct shake_vector {
    const char *name;
    const uint8_t *input;
    size_t input_length;
    size_t output_length;
    const uint8_t *expected128;
    const uint8_t *expected256;
};

#define VECTOR(iname, input, input_len, n)                              \
    {                                                                   \
        #iname " len=" #n, (input), (input_len), (n),                   \
        fips202_shake_128_##iname##_##n,                                \
        fips202_shake_256_##iname##_##n                                 \
    }

static const struct shake_vector vectors[] = {
    VECTOR(empty, empty, 0, 32),   VECTOR(empty, empty, 0, 64),
    VECTOR(empty, empty, 0, 137),  VECTOR(empty, empty, 0, 168),
    VECTOR(empty, empty, 0, 169),  VECTOR(empty, empty, 0, 300),
    VECTOR(empty, empty, 0, 512),  VECTOR(abc, abc, sizeof(abc), 32),
    VECTOR(abc, abc, sizeof(abc), 64), VECTOR(abc, abc, sizeof(abc), 137),
    VECTOR(abc, abc, sizeof(abc), 168), VECTOR(abc, abc, sizeof(abc), 169),
    VECTOR(abc, abc, sizeof(abc), 300), VECTOR(abc, abc, sizeof(abc), 512),
    VECTOR(seq200, seq200, sizeof(seq200), 32),
    VECTOR(seq200, seq200, sizeof(seq200), 64),
    VECTOR(seq200, seq200, sizeof(seq200), 137),
    VECTOR(seq200, seq200, sizeof(seq200), 168),
    VECTOR(seq200, seq200, sizeof(seq200), 169),
    VECTOR(seq200, seq200, sizeof(seq200), 300),
    VECTOR(seq200, seq200, sizeof(seq200), 512),
};

static void test_vector(const struct shake_vector *v)
{
    uint8_t output[512];
    uint8_t block_output[512];
    size_t half = v->input_length / 2;
    size_t done = 0;
    size_t blocks128 = v->output_length / SHAKE128_RATE;
    size_t blocks256 = v->output_length / SHAKE256_RATE;
    char what[128];

    memset(output, 0, sizeof(output));
    shake128(output, v->output_length, v->input, v->input_length);
    snprintf(what, sizeof(what), "shake128 one-shot %s", v->name);
    check(equal(output, v->expected128, v->output_length), what);

    memset(output, 0, sizeof(output));
    shake256(output, v->output_length, v->input, v->input_length);
    snprintf(what, sizeof(what), "shake256 one-shot %s", v->name);
    check(equal(output, v->expected256, v->output_length), what);

    /* Split absorption and repeated squeezing must equal the one-shot result. */
    {
        shake128incctx ctx;
        shake128_inc_init(&ctx);
        shake128_inc_absorb(&ctx, v->input, half);
        shake128_inc_absorb(&ctx, v->input + half, v->input_length - half);
        shake128_inc_finalize(&ctx);
        while (done < v->output_length) {
            size_t chunk = v->output_length - done < 37 ?
                           v->output_length - done : 37;
            shake128_inc_squeeze(output + done, chunk, &ctx);
            done += chunk;
        }
        shake128_inc_ctx_release(&ctx);
        snprintf(what, sizeof(what), "shake128 incremental %s", v->name);
        check(equal(output, v->expected128, v->output_length), what);
    }

    done = 0;
    {
        shake256incctx ctx;
        shake256_inc_init(&ctx);
        shake256_inc_absorb(&ctx, v->input, half);
        shake256_inc_absorb(&ctx, v->input + half, v->input_length - half);
        shake256_inc_finalize(&ctx);
        while (done < v->output_length) {
            size_t chunk = v->output_length - done < 53 ?
                           v->output_length - done : 53;
            shake256_inc_squeeze(output + done, chunk, &ctx);
            done += chunk;
        }
        shake256_inc_ctx_release(&ctx);
        snprintf(what, sizeof(what), "shake256 incremental %s", v->name);
        check(equal(output, v->expected256, v->output_length), what);
    }

    /* The block-oriented API must agree for whole output blocks. */
    if (blocks128 > 0) {
        shake128ctx ctx;
        memset(block_output, 0, sizeof(block_output));
        shake128_absorb(&ctx, v->input, v->input_length);
        shake128_squeezeblocks(block_output, blocks128, &ctx);
        shake128_ctx_release(&ctx);
        snprintf(what, sizeof(what), "shake128 blocks %s", v->name);
        check(equal(block_output, v->expected128,
                    blocks128 * SHAKE128_RATE), what);
    }
    if (blocks256 > 0) {
        shake256ctx ctx;
        memset(block_output, 0, sizeof(block_output));
        shake256_absorb(&ctx, v->input, v->input_length);
        shake256_squeezeblocks(block_output, blocks256, &ctx);
        shake256_ctx_release(&ctx);
        snprintf(what, sizeof(what), "shake256 blocks %s", v->name);
        check(equal(block_output, v->expected256,
                    blocks256 * SHAKE256_RATE), what);
    }
}

/* SHA3 fixed-length outputs from NIST FIPS 202 examples for "" and "abc". */
static const uint8_t sha3_256_empty[32] = {
    0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
    0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
};
static const uint8_t sha3_256_abc[32] = {
    0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
    0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
};
static const uint8_t sha3_384_empty[48] = {
    0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d, 0x01, 0x10, 0x7d, 0x85, 0x2e, 0x4c, 0x24, 0x85,
    0xc5, 0x1a, 0x50, 0xaa, 0xaa, 0x94, 0xfc, 0x61, 0x99, 0x5e, 0x71, 0xbb, 0xee, 0x98, 0x3a, 0x2a,
    0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb, 0x47, 0xfb, 0x6b, 0xd1, 0xe0, 0x58, 0xd5, 0xf0, 0x04,
};
static const uint8_t sha3_384_abc[48] = {
    0xec, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6f, 0xc9, 0x26, 0x45, 0x9f, 0x58, 0xe2, 0xc6, 0xad, 0x8d,
    0xf9, 0xb4, 0x73, 0xcb, 0x0f, 0xc0, 0x8c, 0x25, 0x96, 0xda, 0x7c, 0xf0, 0xe4, 0x9b, 0xe4, 0xb2,
    0x98, 0xd8, 0x8c, 0xea, 0x92, 0x7a, 0xc7, 0xf5, 0x39, 0xf1, 0xed, 0xf2, 0x28, 0x37, 0x6d, 0x25,
};
static const uint8_t sha3_512_empty[64] = {
    0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
    0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59, 0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
    0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c, 0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
    0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3, 0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26,
};
static const uint8_t sha3_512_abc[64] = {
    0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a, 0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e,
    0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d, 0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e,
    0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9, 0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40,
    0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5, 0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0,
};

static void test_sha3(void)
{
    uint8_t out[64];

    sha3_256(out, empty, 0);
    check(equal(out, sha3_256_empty, 32), "sha3-256 empty");
    sha3_256(out, abc, sizeof(abc));
    check(equal(out, sha3_256_abc, 32), "sha3-256 abc");
    sha3_384(out, empty, 0);
    check(equal(out, sha3_384_empty, 48), "sha3-384 empty");
    sha3_384(out, abc, sizeof(abc));
    check(equal(out, sha3_384_abc, 48), "sha3-384 abc");
    sha3_512(out, empty, 0);
    check(equal(out, sha3_512_empty, 64), "sha3-512 empty");
    sha3_512(out, abc, sizeof(abc));
    check(equal(out, sha3_512_abc, 64), "sha3-512 abc");
}

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        test_vector(&vectors[i]);
    }
    test_sha3();

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
