# RSA - Level 4

# See the attachment for the challenge code. The output is:
# 136372941954692995052032614106416002216650352281441768759106047115825257661310123118558086046873251952204915740853517008372422353621244931366409094731856824295828106036399145756514345255241109944294641060644246049854296519101775880563276657142059245230769447888021843340822736997057074223723734593369646608283
# [88934261481985787316571946676203348514352494646042103159736155624287938096099586834729171652139440814472420307071476143907698982272593448957770236088603490101924827608944006107576740571416087954304061091614594794358854353419664581332745351113861171522629631586344259719016707622211007808872462656489173218734, 31191490339291402076171068036548032381977184741778243810947202097002026583133103229115040414216968980627919985794378128894603186334221963211692252394535977554990491215621733091487550326776298499502932523408287882489799200954692353162958794137970552454035789701538315132727860436887544051794011893682559545564]

# === Attack Overview ===
# - Attack Type: Common-Modulus Attack (same modulus nn, two different public exponents e₁, e₂)
# - Mathematical Attack
# - Weakness: Reusing the same RSA modulus with different coprime exponents
# - Brief Attack Description:
#     This attack exploits the situation where the same RSA modulus is used
#     with different public exponents to encrypt the same plaintext message.
#     By using the Extended Euclidean Algorithm, we can find coefficients
#     that allow us to combine the ciphertexts and recover the plaintext
#     without needing to factor the modulus. This is a known weakness in RSA
#     implementations when the same modulus is reused with different coprime
#     public exponents, as it allows for the plaintext to be recovered
#     without the need for private keys or factorization.

# === Attack Steps ===
#  1. Use Extended GCD to find coefficients a, b such that a·e₁ + b·e₂ = 1.
#  2. Compute m = c₁^a · c₂^b mod n (handling negative exponents with modular inverse).
#  3. Convert the recovered message to bytes to reveal the flag.

# === Flag ===
# CRYPTO25{2533166c-ce76-4f5e-b992-f7e4a24d0b97}

from Crypto.Util.number import long_to_bytes, inverse

# Challenge-provided values
n = 136372941954692995052032614106416002216650352281441768759106047115825257661310123118558086046873251952204915740853517008372422353621244931366409094731856824295828106036399145756514345255241109944294641060644246049854296519101775880563276657142059245230769447888021843340822736997057074223723734593369646608283
c1 = 88934261481985787316571946676203348514352494646042103159736155624287938096099586834729171652139440814472420307071476143907698982272593448957770236088603490101924827608944006107576740571416087954304061091614594794358854353419664581332745351113861171522629631586344259719016707622211007808872462656489173218734
c2 = 31191490339291402076171068036548032381977184741778243810947202097002026583133103229115040414216968980627919985794378128894603186334221963211692252394535977554990491215621733091487550326776298499502932523408287882489799200954692353162958794137970552454035789701538315132727860436887544051794011893682559545564
e1, e2 = 31, 71

# The Extended Euclidean Algorithm not only computes the greatest common divisor (gcd) of two integers a and b,
# but also finds integers x and y such that a*x + b*y = gcd(a, b). This property is essential in cryptography,
# especially for attacks like the RSA common modulus attack, because it allows us to express 1 as a linear
# combination of the public exponents (e1 and e2). With these coefficients, we can combine the two ciphertexts
# (encrypted with the same modulus but different exponents) in such a way that the original plaintext can be
# recovered, even without knowing the private key or factoring the modulus. This is why the Extended Euclidean
# Algorithm is used here: it provides the mathematical foundation to "undo" the encryption when the same message
# is encrypted under the same modulus with different, coprime exponents.

# Extended Euclidean Algorithm to find (g, x, y) such that x*a + y*b = g = gcd(a, b)
def extended_gcd(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        g, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return (g, x, y)

def main():
    # Step 1: compute a, b with a*e₁ + b*e₂ = 1
    g, a, b = extended_gcd(e1, e2)
    if g != 1:
        raise ValueError(f"Exponents not coprime: gcd = {g}")

    # Step 2: compute c₁^a mod n and c₂^b mod n, handling negative exponents
    if a < 0:
        c1_part = pow(inverse(c1, n), -a, n)
    else:
        c1_part = pow(c1, a, n)

    if b < 0:
        c2_part = pow(inverse(c2, n), -b, n)
    else:
        c2_part = pow(c2, b, n)

    # Step 3: combine to get plaintext m
    m = (c1_part * c2_part) % n

    # Step 4: convert integer m back to bytes
    flag = long_to_bytes(m)
    print(flag.decode())

if __name__ == '__main__':
    main()
