package io.iohk.protocol.keygen.datastractures.round1

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.hybrid.HybridEncryption
import io.iohk.core.crypto.primitives.blockcipher.{BlockCipher, BlockCipherFactory}
import io.iohk.core.crypto.primitives.blockcipher.BlockCipherFactory.AvailableBlockCiphers
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, DiscreteLogGroupFactory}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.protocol.keygen.datastructures_new.round1.{R1Data, R1DataSerializer, SecretShare, SecretShareSerializer}
import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks

class R1DataTest extends FunSuite with TableDrivenPropertyChecks {

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

  def createSecretShare(receiverId: Int, msg: String, pubKey: PubKey)
                       (implicit group: DiscreteLogGroup, blockCipher: BlockCipher): SecretShare = {
    val message = msg.getBytes
    val ciphertext = HybridEncryption.encrypt(pubKey, message).get
    SecretShare(receiverId, ciphertext)
  }

  test("serialization") {
    forAll(dlogGroups) { implicit group =>
      forAll(blockCiphers) { implicit blockCipher =>
        val (_, pubKey) = encryption.createKeyPair.get

        val issuerId = 5
        val E = for(i <- 0 until 10) yield group.createRandomGroupElement.get
        val S_a = for(i <- 0 until 15) yield createSecretShare(i, "MessageA" + i, pubKey)
        val S_b = for(i <- 0 until 15) yield createSecretShare(i, "MessageB" + i, pubKey)

        val r1Data = R1Data(issuerId, E.toVector, S_a.toVector, S_b.toVector)
        val r1DataBytes = r1Data.bytes
        val r1DataRecovered = R1DataSerializer.parseBytes(r1DataBytes, Some(group -> blockCipher)).get

        require(r1DataRecovered.issuerID == issuerId)
        require(r1DataRecovered.E.size == E.size)
        require(r1DataRecovered.S_a.size == S_a.size)
        require(r1DataRecovered.S_b.size == S_b.size)
        E zip r1DataRecovered.E foreach(e => require(e._1 == e._2))
        S_a zip r1DataRecovered.S_a foreach(s_a => require(s_a._1.bytes.sameElements(s_a._2.bytes)))
        S_b zip r1DataRecovered.S_b foreach(s_b => require(s_b._1.bytes.sameElements(s_b._2.bytes)))
      }
    }
  }
}
