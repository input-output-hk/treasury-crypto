package io.iohk.protocol.common.rnce_encryption

import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc.discreteLog
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.protocol.common.utils.DlogGroupArithmetics.{_}

import scala.util.Try

// Implementation of the RNCE encryption scheme according to the paragraph 4.2 of https://eprint.iacr.org/2004/317.pdf

case class RnceSecretKey(x1: BigInt,
                         x2: BigInt,
                         y1: BigInt,
                         y2: BigInt)

case class RncePublicKey(g1: GroupElement,
                         g2: GroupElement,
                         h:  GroupElement,
                         d:  GroupElement)

case class RnceCiphertext(u1: GroupElement,
                          u2: GroupElement,
                          e:  GroupElement,
                          v:  GroupElement)

case class RnceAuxInfo(alpha: BigInt)

object RnceEncryption {

  private def randZq(implicit group: DiscreteLogGroup) = group.createRandomNumber

  def keygen()(implicit group: DiscreteLogGroup): (RnceSecretKey, RncePublicKey, RnceAuxInfo) = {

    val (x1, x2, y1, y2, alpha) = (randZq, randZq, randZq, randZq, randZq)
    val g1 = group.groupGenerator
    val g2 = exp(g1, alpha)

    (RnceSecretKey(x1, x2, y1, y2),
     RncePublicKey(
       g1, g2,
       h = mul(exp(g1, x1), exp(g2, x2)),
       d = mul(exp(g1, y1), exp(g2, y2))),
     RnceAuxInfo(alpha))
  }

  def encrypt(pk: RncePublicKey, msg: BigInt)
             (implicit group: DiscreteLogGroup): RnceCiphertext = {
    val r = randZq

    RnceCiphertext(
      u1 = exp(pk.g1, r),
      u2 = exp(pk.g2, r),
      e  = mul(exp(pk.g1, msg), exp(pk.h, r)),
      v  = exp(pk.d, r)
    )
  }

  def decrypt(sk: RnceSecretKey, ct: RnceCiphertext)
             (implicit group: DiscreteLogGroup): Try[BigInt] = Try{
    require(mul(exp(ct.u1, sk.y1), exp(ct.u2, sk.y2)).equals(ct.v), "Inconsistent ciphertext")
    discreteLog(
      div(ct.e, mul(exp(ct.u1, sk.x1), exp(ct.u2, sk.x2)))
    ).get
  }

  // 'Fake encryption' section of the RNCE specification
  def fakeCiphertext(sk: RnceSecretKey, pk: RncePublicKey)
             (implicit group: DiscreteLogGroup): RnceCiphertext = {
    val r = randZq
    val u1 = exp(pk.g1, r)
    val u2 = mul(pk.g1, exp(pk.g2, r))

    RnceCiphertext(
      u1, u2,
      e = mul(exp(pk.g1, sk.x2), exp(pk.h, r)),
      v = mul(exp(u1, sk.y1), exp(u2, sk.y2))
    )
  }

  // 'Reveal algorithm' section of the RNCE specification
  def fakeSecretKey(sk: RnceSecretKey, aux: RnceAuxInfo, msg: BigInt)
                   (implicit group: DiscreteLogGroup): RnceSecretKey = {
    val x1_ = (sk.x1 + msg * aux.alpha).mod(group.groupOrder)
    val x2_ = (sk.x2 - msg).mod(group.groupOrder)
    RnceSecretKey(x1_, x2_, sk.y1, sk.y2)
  }
}
