package io.iohk.protocol.voting.preferential.tally.datastructures

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.nizk.{DLEQStandardNIZKProof, DLEQStandardNIZKProofSerializer, ElgamalDecrNIZK}
import io.iohk.protocol.voting.common.Issuer

import scala.util.Try

case class PrefTallyR1Data(issuerID: Int,
                           delegDecryptedC1: Seq[(GroupElement, DLEQStandardNIZKProof)]
                          ) extends BytesSerializable with Issuer {

  override type M = PrefTallyR1Data
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = PrefTallyR1DataSerializer

  override val issuerId: Int = issuerID

  def validate(ctx: CryptoContext,
               issuerPubKey: PubKey,
               encryptedVectorForValidation: Seq[ElGamalCiphertext]): Boolean = Try {
    import ctx.{group, hash}
    require(delegDecryptedC1.length == encryptedVectorForValidation.length, "Wrong number of decryptedC1 elements")

    for (i <- encryptedVectorForValidation.indices) {
      val ciphertext = encryptedVectorForValidation(i)
      val C1sk = delegDecryptedC1(i)._1
      val plaintext = ciphertext.c2.divide(C1sk).get
      val proof = delegDecryptedC1(i)._2

      require(ElgamalDecrNIZK.verifyNIZK(issuerPubKey, ciphertext, plaintext, proof), "Invalid proof")
    }
  }.isSuccess
}

object PrefTallyR1DataSerializer extends Serializer[PrefTallyR1Data, DiscreteLogGroup] {

  override def toBytes(obj: PrefTallyR1Data): Array[Byte] = {
    val decryptedC1Bytes = obj.delegDecryptedC1.foldLeft(Array[Byte]()) { (acc, c1) =>
      val point = c1._1.bytes
      val proof = c1._2.bytes
      Bytes.concat(acc, Array(point.length.toByte), point, proof)
    }
    Bytes.concat(
      Ints.toByteArray(obj.issuerID),
      Shorts.toByteArray(obj.delegDecryptedC1.length.toShort), decryptedC1Bytes)
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[PrefTallyR1Data] = Try {
    val group = decoder.get
    val issuerId = Ints.fromByteArray(bytes.slice(0,4))

    val decryptedC1Len = Shorts.fromByteArray(bytes.slice(4, 6))
    var pos = 6
    val decryptedC1 = (0 until decryptedC1Len).map { _ =>
      val len = bytes(pos)
      val point = group.reconstructGroupElement(bytes.slice(pos+1, pos+1+len)).get
      pos = pos + len + 1
      val proof = DLEQStandardNIZKProofSerializer.parseBytes(bytes.drop(pos), decoder).get
      pos = pos + proof.bytes.length
      (point, proof)
    }

    PrefTallyR1Data(issuerId, decryptedC1)
  }
}
