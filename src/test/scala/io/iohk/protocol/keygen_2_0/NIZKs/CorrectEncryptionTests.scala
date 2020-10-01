package io.iohk.protocol.keygen_2_0.NIZKs

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.NIZKs.CorrectEncryption.Witness
import io.iohk.protocol.keygen_2_0.dlog_encryption.{DLogCiphertext, DLogEncryption, DLogRandomness}
import org.scalatest.FunSuite

import scala.util.Success

class CorrectEncryptionTests extends FunSuite {

  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val n = context.group.groupOrder
  private val dlogGroup = context.group

  import context.group

  private def randomElement = dlogGroup.createRandomNumber //BigInt(n.bitLength, util.Random).mod(n)

  test("randomness_generated"){

    val (privKey, pubKey) = encryption.createKeyPair.get
    val msg = randomElement

    val (ct, r) = DLogEncryption.encrypt(msg, pubKey).get

    val ce = CorrectEncryption(ct, pubKey, dlogGroup)
    val proof = ce.prove(Witness(msg, r, dlogGroup))

    assert(ce.verify(proof))
  }

  test("randomness_parameterized"){
    def encrypt(msg: BigInt, pubKey: PubKey): Option[(DLogCiphertext, DLogRandomness)] = {
      for(_ <- 0 until 10){ // 10 attempts to encrypt with a new randomness
        DLogEncryption.encrypt(msg, randomElement, pubKey) match {
          case Success(res) => return Some(res)
          case _ =>
        }
      }
      None
    }
    val (privKey, pubKey) = encryption.createKeyPair.get
    val msg = randomElement

    val (ct, r) = encrypt(msg, pubKey).get

    val ce = CorrectEncryption(ct, pubKey, dlogGroup)
    val proof = ce.prove(Witness(msg, r, dlogGroup))

    assert(ce.verify(proof))
  }
}
