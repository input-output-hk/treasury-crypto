package treasury.crypto.nizk.unitvectornizk

import java.math.BigInteger

import treasury.crypto.core.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import treasury.crypto.core.encryption.encryption.{PubKey, Randomness}
import treasury.crypto.core.primitives.dlog.DiscreteLogGroup
import treasury.crypto.core.primitives.hash.CryptographicHash

import scala.util.Try

/* This class implements the protocol developed by prof. Bingsheng Zhang to prove that a ciphertext encrypts
 * zero or one. Ciphertext is obtained with Lifted Elgamal encryption scheme. */

object ZeroOrOneBZNIZK {
  case class ZeroOrOneBZNIZKProof(A: ElGamalCiphertext, B: ElGamalCiphertext, f: BigInt, w: BigInt, v: BigInt)

  def produceNIZK(pubKey: PubKey, plaintext: BigInt, ciphertext: ElGamalCiphertext, r: Randomness)
                 (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Try[ZeroOrOneBZNIZKProof] = Try {
    val beta = dlogGroup.createRandomNumber
    val gamma = dlogGroup.createRandomNumber
    val delta = dlogGroup.createRandomNumber

    val B = LiftedElGamalEnc.encrypt(pubKey, gamma, beta).get
    val A = LiftedElGamalEnc.encrypt(pubKey, delta, plaintext * beta).get

    val e = new BigInteger(hashFunction.hash {
      pubKey.bytes ++
      ciphertext.bytes ++
      B.bytes ++
      A.bytes
    }).mod(dlogGroup.groupOrder)

    val f = (plaintext * e + beta) mod(dlogGroup.groupOrder)
    val w = (r * e + gamma) mod(dlogGroup.groupOrder)
    val v = ((e - f) * r + delta) mod(dlogGroup.groupOrder)

    ZeroOrOneBZNIZKProof(A, B, f, w, v)
  }

  def verifyNIZK(pubKey: PubKey, ciphertext: ElGamalCiphertext, proof: ZeroOrOneBZNIZKProof)
                (implicit dlogGroup: DiscreteLogGroup, hashFunction: CryptographicHash): Boolean = Try {
    val e = new BigInteger(hashFunction.hash {
      pubKey.bytes ++
      ciphertext.bytes ++
      proof.B.bytes ++
      proof.A.bytes
    }).mod(dlogGroup.groupOrder)

    val ceB = ciphertext.pow(e).get * proof.B
    val encfw = LiftedElGamalEnc.encrypt(pubKey, proof.w, proof.f).get
    val check1 = ceB == encfw

    val cefA = ciphertext.pow(e - proof.f).get * proof.A
    val enc0v = LiftedElGamalEnc.encrypt(pubKey, proof.v, 0).get
    val check2 = cefA == enc0v

    check1 && check2
  }.getOrElse(false)
}
