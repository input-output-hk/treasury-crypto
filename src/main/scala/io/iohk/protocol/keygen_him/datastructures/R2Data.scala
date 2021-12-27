package io.iohk.protocol.keygen_him.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.common.utils.GroupElementSerializer
import io.iohk.protocol.common.utils.Serialization.{parseSeq, serializeSeq}

import scala.util.Try

case class R2Data(senderID: Int,
                  coeffsCommitments: Seq[GroupElement]) // g^a commitments
  extends BytesSerializable {
  override type M = R2Data
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = R2DataSerializer
}

object R2DataSerializer extends Serializer[R2Data, DiscreteLogGroup]{
  def toBytes(obj: R2Data): Array[Byte] = {
    Bytes.concat(
      Ints.toByteArray(obj.senderID),
      serializeSeq(obj.coeffsCommitments, GroupElementSerializer)
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[R2Data] = Try{
    implicit val group: DiscreteLogGroup = decoder.get

    val senderID = Ints.fromByteArray(bytes.slice(0, Ints.BYTES))

    val coeffsCommitments = parseSeq(
      bytes.slice(Ints.BYTES, bytes.length),
      GroupElementSerializer
    ).get._1

    R2Data(senderID, coeffsCommitments)
  }
}
