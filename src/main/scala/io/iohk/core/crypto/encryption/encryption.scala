package io.iohk.core.crypto

import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}

import scala.util.Try

package object encryption {

  type PubKey = GroupElement
  type PrivKey = BigInt
  type KeyPair = (PrivKey, PubKey)
  type Randomness = BigInt

  def createKeyPair(implicit dlogGroup: DiscreteLogGroup): Try[(PrivKey, PubKey)] = {
    val privKey = dlogGroup.createRandomNumber
    dlogGroup.exponentiate(dlogGroup.groupGenerator, privKey).map { pubKey =>
      (privKey, pubKey)
    }
  }
}
