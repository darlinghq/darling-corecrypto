#include <corecrypto/cczp.h>
#include <stdio.h>
#include <stdlib.h>

void cczp_init(cczp_t zp)
{
#if DEBUG
	printf("DARLING CRYPTO IMPL: %s\n", __PRETTY_FUNCTION__);
#endif
	cc_unit *recip = CCZP_RECIP(zp);
	memset(recip, 0, ccn_sizeof_n(CCZP_N(zp)));
	zp.zp->mod_prime = &cczp_mod;
}

void cczp_mod(cczp_const_t zp, cc_unit *r, const cc_unit *s2n, cc_ws_t ws)
{
#if DEBUG
	printf("DARLING CRYPTO IMPL: %s\n", __PRETTY_FUNCTION__);
#endif
	/*
if D = 0 then error(DivisionByZeroException) end
Q := 0                  -- Initialize quotient and remainder to zero
R := 0                     
for i := n − 1 .. 0 do  -- Where n is number of bits in N
  R := R << 1           -- Left-shift R by 1 bit
  R(0) := N(i)          -- Set the least-significant bit of R equal to bit i of the numerator
  if R ≥ D then
    R := R − D
    Q(i) := 1
  end
end
*/
	const cc_unit *mod = cczp_prime(zp);
	const cc_size n = cczp_n(zp);
	const cc_size s2n_bits = ccn_bitlen(n*2, s2n);

	for (int i = s2n_bits-1; i >= 0; i--)
	{
		cc_unit leftmost_bit = ccn_shift_left(n, r, r, 1);
		if (leftmost_bit != 0)
		{
			printf("%s: unexpected overflow\n", __PRETTY_FUNCTION__);
		}

		// get mask for nth bit
		cc_unit mask = 1 << (i % CCN_UNIT_SIZE);

		r[0] |= (s2n[i/CCN_UNIT_SIZE] & mask) >> (i % CCN_UNIT_SIZE);

		if (ccn_cmp(n, r, mod) > 0)
		{
			ccn_sub(n, r, r, mod);
		}
	}
}

/*
 * r = (m^e) mod CCZP_PRIME(zp)
 *
 * Implementation guide: https://en.wikipedia.org/wiki/Modular_exponentiation#Right-to-left_binary_method
 *
 * zp:	ZP data structure
 * r:	Result pointer, cc_unit array size CCZP_N(zp)
 * m:	Message, also size CCZP_N(zp)
 * e:	Exponent, also size CCZP_N(zp)
 */
void cczp_power(cczp_const_t zp, cc_unit *r, const cc_unit *m,
                const cc_unit *e)
{
#if DEBUG
	printf("DARLING CRYPTO IMPL: %s\n", __PRETTY_FUNCTION__);
#endif

/*
 * function modular_pow(base, exponent, modulus) is
    if modulus = 1 then
        return 0
    Assert :: (modulus - 1) * (modulus - 1) does not overflow base
    result := 1
    base := base mod modulus
    while exponent > 0 do
        if (exponent mod 2 == 1) then
            result := (result * base) mod modulus
        exponent := exponent >> 1
        base := (base * base) mod modulus
    return result
*/
	cc_size n = cczp_n(zp);
	cc_size n_sizeof = ccn_sizeof_n(n);

	// Initialize result
	memset(r, 0, n_sizeof);

	// If mod equals 1, return zero
	uint8_t one = 1;
	ccn_read_uint(n, r, sizeof(int), &one);
	if (ccn_cmp(n, r, cczp_prime(zp)) == 0)
	{
		// Return zero as result, x mod 1 is zero
		one = 0;
		ccn_read_uint(n, r, sizeof(uint8_t), &one);
		return;
	}

	// TODO: Assert :: (modulus - 1) * (modulus - 1) does not overflow base
	
	// Result is still one at this point
	
	cc_unit *base = malloc(n_sizeof*2);
	memset(base, 0, n_sizeof*2);
	memcpy(base, m, n_sizeof);

	// Use a workspace size 2n+1 because ws.end is non-inclusive end pointer
	cc_ws_t ws;
	ws->start = malloc(n*2+1);
	ws->end = ws->start+(n*2);

	// ccn integers are little endian, so it's OK that the 3rd parameter
	// is length 2n (despite not needing it)
	cczp_mod_prime(zp)(zp, base, base, ws);

	free(ws->start);
}
