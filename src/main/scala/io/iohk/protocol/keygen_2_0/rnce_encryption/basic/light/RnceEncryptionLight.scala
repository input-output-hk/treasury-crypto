package io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light

import io.iohk.core.crypto.encryption.Randomness
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc.discreteLog
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.{RnceCiphertextLight, RnceCrsLight, RncePublicKeyLight, RnceSecretKeyLight}
import io.iohk.protocol.keygen_2_0.utils.DlogGroupArithmetics.{div, exp, mul}

import scala.util.Try

// Light version of the RNCE encryption scheme

object RnceEncryptionLight {

  private def randZq(implicit group: DiscreteLogGroup) = group.createRandomNumber

  def keygen(crs: RnceCrsLight)(implicit group: DiscreteLogGroup): (RnceSecretKeyLight, RncePublicKeyLight) = {

    val (x1, x2) = (randZq, randZq)
    (
      RnceSecretKeyLight(x1, x2),
      data.RncePublicKeyLight(mul(exp(crs.g1, x1), exp(crs.g2, x2)))
    )
  }

  def encrypt(pk: RncePublicKeyLight, msg: BigInt, crs: RnceCrsLight)
             (implicit group: DiscreteLogGroup): (RnceCiphertextLight, Randomness) = {
    val r = randZq

    (
      data.RnceCiphertextLight(
        u1 = exp(crs.g1, r),
        u2 = exp(crs.g2, r),
        e  = mul(exp(crs.g1, msg), exp(pk.h, r))
      ), r
    )
  }

  def decrypt(sk: RnceSecretKeyLight, ct: RnceCiphertextLight, crs: RnceCrsLight)
             (implicit group: DiscreteLogGroup): Try[BigInt] = Try{
    discreteLog(
      div(ct.e, mul(exp(ct.u1, sk.x1), exp(ct.u2, sk.x2))),
      Some(crs.g1)
    ).get
  }

  // 'Fake encryption' section of the RNCE specification
  def fakeCiphertext(sk: RnceSecretKeyLight, pk: RncePublicKeyLight, crs: RnceCrsLight)
                    (implicit group: DiscreteLogGroup): RnceCiphertextLight = {
    val r = randZq
    val u1 = exp(crs.g1, r)
    val u2 = mul(crs.g1, exp(crs.g2, r))

    RnceCiphertextLight(
      u1, u2,
      e = mul(exp(crs.g1, sk.x2), exp(pk.h, r))
    )
  }

  // 'Reveal algorithm' section of the RNCE specification
  def fakeSecretKey(sk: RnceSecretKeyLight, alpha: BigInt, msg: BigInt)
                   (implicit group: DiscreteLogGroup): RnceSecretKeyLight = {
    val x1_ = (sk.x1 + msg * alpha).mod(group.groupOrder)
    val x2_ = (sk.x2 - msg).mod(group.groupOrder)
    RnceSecretKeyLight(x1_, x2_)
  }
}
