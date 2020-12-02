package io.iohk.protocol.keygen_2_0.utils

import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}

object DlogGroupArithmetics {

  def mul(g1: GroupElement, g2: GroupElement)(implicit dlogGroup: DiscreteLogGroup): GroupElement = {
    dlogGroup.multiply(g1, g2).get
  }

  def div(g1: GroupElement, g2: GroupElement)(implicit dlogGroup: DiscreteLogGroup): GroupElement = {
    dlogGroup.divide(g1, g2).get
  }

  def inv(g: GroupElement)(implicit dlogGroup: DiscreteLogGroup): GroupElement = {
    dlogGroup.inverse(g).get
  }

  def exp(base: GroupElement, exponent: BigInt)(implicit dlogGroup: DiscreteLogGroup): GroupElement = {
    dlogGroup.exponentiate(base, exponent).get
  }
}
