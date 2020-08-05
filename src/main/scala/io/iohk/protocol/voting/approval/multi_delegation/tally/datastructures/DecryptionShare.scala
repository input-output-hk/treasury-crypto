package io.iohk.protocol.voting.approval.multi_delegation.tally.datastructures

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.nizk.{ElgamalDecrNIZK, ElgamalDecrNIZKProof, ElgamalDecrNIZKProofSerializer}

import scala.util.Try


case class DecryptionShare(proposalId:   Int,
                           decryptedC1:  Seq[(GroupElement, ElgamalDecrNIZKProof)]
                          ) extends HasSize with BytesSerializable {

  override type M = DecryptionShare
  override type DECODER = DiscreteLogGroup
  override val serializer = DecryptionShareSerializer

  def size: Int = bytes.length

  def validate(ctx: CryptoContext,
               issuerPubKey: PubKey,
               encryptedVectorForValidation: Seq[ElGamalCiphertext]): Try[Unit] = Try {
    import ctx.{group, hash}
    require(decryptedC1.length == encryptedVectorForValidation.length, "Wrong number of decryptedC1 elements")

    for (i <- encryptedVectorForValidation.indices) {
      val ciphertext = encryptedVectorForValidation(i)
      val C1sk = decryptedC1(i)._1
      val plaintext = ciphertext.c2.divide(C1sk).get
      val proof = decryptedC1(i)._2

      require(ElgamalDecrNIZK.verifyNIZK(issuerPubKey, ciphertext, plaintext, proof), "Invalid proof")
    }
  }
}

object DecryptionShareSerializer extends Serializer[DecryptionShare, DiscreteLogGroup] {

  override def toBytes(obj: DecryptionShare): Array[Byte] = {
    val decryptedC1Bytes = obj.decryptedC1.foldLeft(Array[Byte]()) { (acc, c1) =>
      val point = c1._1.bytes
      val proof = c1._2.bytes
      Bytes.concat(acc, Array(point.length.toByte), point, proof)
    }
    Bytes.concat(
      Ints.toByteArray(obj.proposalId),
      Shorts.toByteArray(obj.decryptedC1.length.toShort), decryptedC1Bytes,
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[DecryptionShare] = Try {
    val group = decoder.get
    val proposalID = Ints.fromByteArray(bytes.slice(0,4))

    val decryptedC1Len = Shorts.fromByteArray(bytes.slice(4, 6))
    var pos = 6
    val decryptedC1 = (0 until decryptedC1Len).map { _ =>
      val len = bytes(pos)
      val point = group.reconstructGroupElement(bytes.slice(pos+1, pos+1+len)).get
      pos = pos + len + 1
      val proof = ElgamalDecrNIZKProofSerializer.parseBytes(bytes.drop(pos), decoder).get
      pos = pos + proof.bytes.length
      (point, proof)
    }

    DecryptionShare(proposalID, decryptedC1)
  }
}
