package io.iohk.protocol

import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext

package object voting {

  case class UnitVector(delegations: Vector[ElGamalCiphertext],
                        choice: Vector[ElGamalCiphertext]) {
    def combine = delegations ++ choice
  }
}
