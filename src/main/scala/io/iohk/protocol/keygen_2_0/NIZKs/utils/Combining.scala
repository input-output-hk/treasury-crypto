package io.iohk.protocol.keygen_2_0.NIZKs.utils

import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.protocol.keygen_2_0.math.Polynomial
import io.iohk.protocol.keygen_2_0.utils.DlogGroupArithmetics.{exp, mul}

object Combining {

  def combine(scalars: Seq[BigInt], lambda: BigInt)
             (implicit dlogGroup: DiscreteLogGroup): BigInt = {
    Polynomial(dlogGroup, scalars.length, BigInt(0), scalars).evaluate(lambda)
  }

  def combine(elements: Seq[GroupElement], lambda: BigInt)
             (implicit dlogGroup: DiscreteLogGroup): GroupElement = {
    elements.zipWithIndex.foldLeft(dlogGroup.groupIdentity){
      (result, element_index) =>
        val (element, i) = element_index
        mul(result, exp(element, lambda.pow(i + 1).mod(dlogGroup.groupOrder)))
    }
  }
}
