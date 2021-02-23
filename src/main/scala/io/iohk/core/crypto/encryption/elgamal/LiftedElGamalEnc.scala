package io.iohk.core.crypto.encryption.elgamal

import io.iohk.core.crypto.encryption.{PrivKey, PubKey, Randomness}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}

import scala.util.Try

/*
* Implements Lifted ElGamal assymetric encryption scheme where message is represented as a scalar.
*/
object LiftedElGamalEnc {

  /* Message to be encrypted should be in range: msg (mod G) = [0 .. MSG_RANGE-1], G is a group order */
  //val MSG_RANGE = BigInt("1048576") // 2^20
  val MSG_RANGE = BigInt("268435456") // 2^28

  /* Lifted ElGamal is based on classical ElGamal where point for dectyption is derived by epnonentiating group generator to msg */
  def encrypt(pubKey: PubKey, rand: Randomness, msg: BigInt)(implicit dlogGroup: DiscreteLogGroup): Try[ElGamalCiphertext] =  {
    dlogGroup.exponentiate(dlogGroup.groupGenerator, msg).flatMap { p =>
      ElGamalEnc.encrypt(pubKey, rand, p)
    }
  }

  def encrypt(pubKey: PubKey, msg: BigInt)(implicit dlogGroup: DiscreteLogGroup): Try[(ElGamalCiphertext, Randomness)] = {
    val rand = dlogGroup.createRandomNumber
    LiftedElGamalEnc.encrypt(pubKey, rand, msg).map((_, rand))
  }

  /*
  * Decryption envolves solving discrete log for the decrypted point. It is assumed that the used exponent is not
  * bigger than MAX_INTEGER, otherwise an exception will be thrown.
  */
  def decrypt(privKey: PrivKey, ciphertext: ElGamalCiphertext)(implicit dlogGroup: DiscreteLogGroup): Try[BigInt] = {
    ElGamalEnc.decrypt(privKey, ciphertext).flatMap { point =>
      discreteLog(point)
    }
  }

  /* Solve discrete logarithm for m*G. Assuming that the exponent space is not big */
  def discreteLog(point: GroupElement)(implicit dlogGroup: DiscreteLogGroup): Try[BigInt] = Try {
    var P = dlogGroup.groupGenerator

    if (point.equals(dlogGroup.groupIdentity))
      BigInt(0)
    else if (point.equals(P))
      BigInt(1)
    else {
      /* exponent is allowed in range 1 .. MSG_RANGE */
      var exponent = 1
      while(exponent < MSG_RANGE && P.equals(point) == false) {
        exponent += 1
        // we are simply multiplying generator to the accumulator on each iteration since it is faster then exponentiate generator each time
        P = dlogGroup.multiply(P, dlogGroup.groupGenerator).get
      }
      if (exponent < MSG_RANGE)
        exponent // we found valid exponent!
      else
        throw new IllegalArgumentException(s"Can not find discrete logarithm for point $point")
    }
  }
}
