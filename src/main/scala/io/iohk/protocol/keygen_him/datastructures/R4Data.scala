package io.iohk.protocol.keygen_him.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize
import io.iohk.protocol.common.utils.GroupElementSerializer
import io.iohk.protocol.common.utils.Serialization.{parseSeq, serializeSeq}

import scala.util.Try

case class R4Data(senderID: Int,
                  globalPubKeys: Seq[GroupElement])
  extends BytesSerializable with HasSize {
  override type M = R4Data
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = R4DataSerializer

  def size: Int = bytes.length
}

object R4DataSerializer extends Serializer[R4Data, DiscreteLogGroup]{
  def toBytes(obj: R4Data): Array[Byte] = {
    Bytes.concat(
    Ints.toByteArray(obj.senderID),
    serializeSeq(obj.globalPubKeys, GroupElementSerializer)
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup] = None): Try[R4Data] = Try{
    implicit val group: DiscreteLogGroup = decoder.get

    val senderID = Ints.fromByteArray(bytes.slice(0, Ints.BYTES))

    val globalPubKeys = parseSeq(
      bytes.slice(Ints.BYTES, bytes.length),
      GroupElementSerializer
    ).get._1

    R4Data(senderID, globalPubKeys)
  }
}
