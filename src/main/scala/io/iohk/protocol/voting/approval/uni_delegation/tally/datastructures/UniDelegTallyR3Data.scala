package io.iohk.protocol.voting.approval.uni_delegation.tally.datastructures

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.nizk.{DLEQStandardNIZKProof, DLEQStandardNIZKProofSerializer, ElgamalDecrNIZK}
import io.iohk.protocol.voting.common.Issuer

import scala.util.Try

case class UniDelegTallyR3Data (issuerID: Int,
                                choicesDecryptedC1: List[Seq[(GroupElement, DLEQStandardNIZKProof)]],
                               ) extends BytesSerializable with Issuer {

  override type M = UniDelegTallyR3Data
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = UniDelegTallyR3DataSerializer

  override val issuerId: Int = issuerID

  def validate(ctx: CryptoContext,
               issuerPubKey: PubKey,
               encryptedChoicesForValidation: List[Seq[ElGamalCiphertext]]): Boolean = Try {
    import ctx.{group, hash}
    require(choicesDecryptedC1.length == encryptedChoicesForValidation.length, "Wrong number of decrypted vectors (proposals)")

    for (i <- encryptedChoicesForValidation.indices) {
      val shares = choicesDecryptedC1(i)
      val encryption = encryptedChoicesForValidation(i)
      require(shares.length == encryption.length)
      for (i <- encryption.indices) {
        val ciphertext = encryption(i)
        val C1sk = shares(i)._1
        val plaintext = ciphertext.c2.divide(C1sk).get
        val proof = shares(i)._2
        require(ElgamalDecrNIZK.verifyNIZK(issuerPubKey, ciphertext, plaintext, proof), "Invalid proof")
      }
    }
  }.isSuccess
}

object UniDelegTallyR3DataSerializer extends Serializer[UniDelegTallyR3Data, DiscreteLogGroup] {

  override def toBytes(obj: UniDelegTallyR3Data): Array[Byte] = {
    val decryptedC1Bytes = obj.choicesDecryptedC1.foldLeft(Array[Byte]()) { (acc, v) =>
      val vBytes = v.foldLeft(Array[Byte]()) { (acc2, c1) =>
        val point = c1._1.bytes
        val proof = c1._2.bytes
        Bytes.concat(acc2, Array(point.length.toByte), point, proof)
      }
      Bytes.concat(acc, Shorts.toByteArray(v.length.toShort), vBytes)
    }
    Bytes.concat(
      Ints.toByteArray(obj.issuerID),
      Shorts.toByteArray(obj.choicesDecryptedC1.length.toShort), decryptedC1Bytes)
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[UniDelegTallyR3Data] = Try {
    val group = decoder.get
    val issuerId = Ints.fromByteArray(bytes.slice(0,4))

    val decryptedC1Len = Shorts.fromByteArray(bytes.slice(4, 6))
    var pos = 6
    val decryptedC1 = (0 until decryptedC1Len).map { _ =>
      val vLen = Shorts.fromByteArray(bytes.slice(pos, pos+2))
      pos += 2
      (0 until vLen).map { _ =>
        val len = bytes(pos)
        val point = group.reconstructGroupElement(bytes.slice(pos + 1, pos + 1 + len)).get
        pos = pos + len + 1
        val proof = DLEQStandardNIZKProofSerializer.parseBytes(bytes.drop(pos), decoder).get
        pos = pos + proof.bytes.length
        (point, proof)
      }.toSeq
    }.toList

    UniDelegTallyR3Data(issuerId, decryptedC1)
  }
}