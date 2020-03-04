package io.iohk.protocol.keygen.datastructures

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core.Point
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize
import io.iohk.protocol.nizk.{ElgamalDecrNIZKProof, ElgamalDecrNIZKProofSerializer}

import scala.util.Try

//----------------------------------------------------------
// Tally decryption data structures
//
case class C1Share(
    proposalId:   Int,
    issuerID:     Integer,
    decryptedC1:  Seq[(Point, ElgamalDecrNIZKProof)]
) extends HasSize with BytesSerializable {

  override type M = C1Share
  override type DECODER = DiscreteLogGroup
  override val serializer = C1ShareSerializer

  def size: Int = bytes.length
}

object C1ShareSerializer extends Serializer[C1Share, DiscreteLogGroup] {

  override def toBytes(obj: C1Share): Array[Byte] = {
    val decryptedC1Bytes = obj.decryptedC1.foldLeft(Array[Byte]()) { (acc, c1) =>
      val point = c1._1.bytes
      val proof = c1._2.bytes
      Bytes.concat(acc, Array(point.length.toByte), point, proof)
    }
    Bytes.concat(
      Ints.toByteArray(obj.proposalId),
      Ints.toByteArray(obj.issuerID),
      Shorts.toByteArray(obj.decryptedC1.length.toShort), decryptedC1Bytes,
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[C1Share] = Try {
    val group = decoder.get
    val proposalID = Ints.fromByteArray(bytes.slice(0,4))
    val issuerID = Ints.fromByteArray(bytes.slice(4,8))

    val decryptedC1Len = Shorts.fromByteArray(bytes.slice(8, 10))
    var pos = 10
    val decryptedC1 = (0 until decryptedC1Len).map { _ =>
      val len = bytes(pos)
      val point = group.reconstructGroupElement(bytes.slice(pos+1, pos+1+len)).get
      pos = pos + len + 1
      val proof = ElgamalDecrNIZKProofSerializer.parseBytes(bytes.drop(pos), decoder).get
      pos = pos + proof.bytes.length
      (point, proof)
    }

    C1Share(proposalID, issuerID, decryptedC1)
  }
}
