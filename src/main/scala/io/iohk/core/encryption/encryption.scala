package io.iohk.core

import io.iohk.core.primitives.dlog.{DiscreteLogGroup, GroupElement}

import scala.util.Try

package object encryption {

  type PubKey = GroupElement
  type PrivKey = BigInt
  type Randomness = BigInt

  def createKeyPair(implicit dlogGroup: DiscreteLogGroup): Try[(PrivKey, PubKey)] = {
    val privKey = dlogGroup.createRandomNumber
    dlogGroup.exponentiate(dlogGroup.groupGenerator, privKey).map { pubKey =>
      (privKey, pubKey)
    }
  }
}
