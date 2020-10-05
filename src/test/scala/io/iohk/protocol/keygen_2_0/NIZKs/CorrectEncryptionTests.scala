package io.iohk.protocol.keygen_2_0.NIZKs

import io.iohk.core.crypto.encryption
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.NIZKs.CorrectEncryption.Witness
import io.iohk.protocol.keygen_2_0.dlog_encryption.{DLogCiphertext, DLogEncryption, DLogRandomness}
import org.scalatest.FunSuite

class CorrectEncryptionTests extends FunSuite {

  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val n = context.group.groupOrder
  private val dlogGroup = context.group

  import context.group

  private def randomElement = dlogGroup.createRandomNumber //BigInt(n.bitLength, util.Random).mod(n)

  test("CorrectEncryption"){

    val (privKey, pubKey) = encryption.createKeyPair.get
    val msg = randomElement

    val (ct, r) = DLogEncryption.encrypt(msg, pubKey).get

    val ce = CorrectEncryption(ct, pubKey, dlogGroup)
    val proof = ce.prove(Witness(msg, r, dlogGroup))

    assert(ce.verify(proof))
  }
}
