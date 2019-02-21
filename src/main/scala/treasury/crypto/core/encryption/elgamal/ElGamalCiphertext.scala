package treasury.crypto.core.encryption.elgamal

import treasury.crypto.core.primitives.dlog.GroupElement

/*
 * Represents a ciphertext for the ElGamal assymetric cryptosystem
 */
case class ElGamalCiphertext(c1: GroupElement, c2: GroupElement)
