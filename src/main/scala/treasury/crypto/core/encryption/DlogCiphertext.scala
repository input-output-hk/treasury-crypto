package treasury.crypto.core.encryption

import treasury.crypto.core.primitives.dlog.GroupElement

/*
 * Represents a ciphertext for an assymetric cryptosystem that is based on discrete log problem
 */
case class DlogCiphertext(c1: GroupElement, c2: GroupElement)
