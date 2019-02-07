package treasury.crypto.core.encryption

import treasury.crypto.core.primitives.dlog.{DiscreteLogGroup, GroupElement}

import scala.util.Try

/*
* Implements classic ElGamal assymetric encryption scheme where message is represented as the group element
*/
class ElGamalEnc(val dlogGroup: DiscreteLogGroup) {

  def encrypt(pubKey: PubKey, rand: Randomness, msg: GroupElement): Try[DlogCiphertext] =
    ElGamalEnc.encrypt(dlogGroup, pubKey, rand, msg)

  def encrypt(pubKey: PubKey, msg: GroupElement): Try[(DlogCiphertext, Randomness)] = {
    val rand = dlogGroup.createRandomNumber
    ElGamalEnc.encrypt(dlogGroup, pubKey, rand, msg).map((_, rand))
  }

  def decrypt(privKey: PrivKey, ciphertext: DlogCiphertext): Try[GroupElement] =
    ElGamalEnc.decrypt(dlogGroup, privKey, ciphertext)
}

object ElGamalEnc {

  def encrypt(dlogGroup: DiscreteLogGroup, pubKey: PubKey, rand: Randomness, msg: GroupElement): Try[DlogCiphertext] = Try {
    val rG = dlogGroup.exponentiate(dlogGroup.groupGenerator, rand).get
    val rPk = dlogGroup.exponentiate(pubKey, rand).get
    val MrPk = dlogGroup.multiply(rPk, msg).get
    DlogCiphertext(rG, MrPk)
  }

  def decrypt(dlogGroup: DiscreteLogGroup, privKey: PrivKey, ciphertext: DlogCiphertext): Try[GroupElement] = Try {
    val rPk = dlogGroup.exponentiate(ciphertext.c1, privKey).get
    dlogGroup.divide(ciphertext.c2, rPk).get
  }
}
