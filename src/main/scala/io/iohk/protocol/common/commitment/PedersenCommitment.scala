package io.iohk.protocol.common.commitment

import io.iohk.core.crypto.encryption.Randomness
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.protocol.common.utils.DlogGroupArithmetics.{exp, mul}

case class PedersenCommitment(g: GroupElement,
                              h: GroupElement)
                             (implicit group: DiscreteLogGroup){
  def get(m: BigInt, r: Randomness): GroupElement = {
    mul(exp(g, m), exp(h, r))
  }
}
