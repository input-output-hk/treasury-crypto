package io.iohk.protocol.keygen.datastractures.round1

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.hybrid.{HybridEncryption, HybridPlaintext, HybridPlaintextSerializer}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipherFactory
import io.iohk.core.crypto.primitives.blockcipher.BlockCipherFactory.AvailableBlockCiphers
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.protocol.keygen.datastructures_new.round1.{SecretShare, SecretShareSerializer}
import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks

class SecretShareTest extends FunSuite with TableDrivenPropertyChecks {

  val dlogGroups =
    Table(
      "group",
      AvailableGroups.values.toSeq.map(g => DiscreteLogGroupFactory.constructDlogGroup(g).get):_*
    )

  val blockCiphers =
    Table(
      "blockCipher",
      AvailableBlockCiphers.values.toSeq.map(c => BlockCipherFactory.constructBlockCipher(c).get):_*
    )

  test("serialization") {
    forAll(dlogGroups) { implicit group =>
      forAll(blockCiphers) { implicit blockCipher =>
        val receiverId = 223
        val message = "Message".getBytes
        val (privKey, pubKey) = encryption.createKeyPair.get

        val ciphertext = HybridEncryption.encrypt(pubKey, message).get
        val secretShare = SecretShare(receiverId, ciphertext)
        val recoveredShare = SecretShareSerializer.parseBytes(secretShare.bytes, Some(group -> blockCipher)).get
        val decryptedMsg = HybridEncryption.decrypt(privKey, ciphertext).get.decryptedMessage

        require(recoveredShare.receiverID == receiverId)
        require(recoveredShare.S.bytes.sameElements(ciphertext.bytes))
        require(decryptedMsg.sameElements(message))
      }
    }
  }
}
