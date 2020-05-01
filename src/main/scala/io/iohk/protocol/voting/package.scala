package io.iohk.protocol

import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext

package object voting {

  object VotingOptions extends Enumeration {
    val Yes, No, Abstain = Value
  }

  case class UnitVector(delegations: Vector[ElGamalCiphertext],
                        choice: Vector[ElGamalCiphertext]) {
    def combine = delegations ++ choice
  }
}
