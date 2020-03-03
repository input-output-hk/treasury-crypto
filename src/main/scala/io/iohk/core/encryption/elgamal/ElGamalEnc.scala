package io.iohk.core.encryption.elgamal

import io.iohk.core.encryption.{PrivKey, PubKey, Randomness}
import io.iohk.core.primitives.dlog.{DiscreteLogGroup, GroupElement}

import scala.util.Try

/*
* Implements classic ElGamal assymetric encryption scheme where message is represented as the group element
*/
object ElGamalEnc {

  def encrypt(pubKey: PubKey, msg: GroupElement)(implicit dlogGroup: DiscreteLogGroup): Try[(ElGamalCiphertext, Randomness)] = {
    val rand = dlogGroup.createRandomNumber
    ElGamalEnc.encrypt(pubKey, rand, msg).map((_, rand))
  }

  def encrypt(pubKey: PubKey, rand: Randomness, msg: GroupElement)(implicit dlogGroup: DiscreteLogGroup): Try[ElGamalCiphertext] = Try {
    val rG = dlogGroup.exponentiate(dlogGroup.groupGenerator, rand).get
    val rPk = dlogGroup.exponentiate(pubKey, rand).get
    val MrPk = dlogGroup.multiply(rPk, msg).get
    ElGamalCiphertext(rG, MrPk)
  }

  def decrypt(privKey: PrivKey, ciphertext: ElGamalCiphertext)(implicit dlogGroup: DiscreteLogGroup): Try[GroupElement] = Try {
    val rPk = dlogGroup.exponentiate(ciphertext.c1, privKey).get
    dlogGroup.divide(ciphertext.c2, rPk).get
  }
}
