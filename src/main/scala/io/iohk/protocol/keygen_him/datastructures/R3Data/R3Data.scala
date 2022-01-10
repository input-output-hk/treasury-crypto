package io.iohk.protocol.keygen_him.datastructures.R3Data

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize
import io.iohk.protocol.common.utils.Serialization.{parseSeq, serializeSeq}

import scala.util.Try

case class R3Data(senderID: Int,
                  complaints: Seq[Complaint])
  extends BytesSerializable with HasSize {
  override type M = R3Data
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = R3DataSerializer
  def size: Int = bytes.length
}

object R3DataSerializer extends Serializer[R3Data, DiscreteLogGroup]{
  def toBytes(obj: R3Data): Array[Byte] = {
    Bytes.concat(
      Ints.toByteArray(obj.senderID),
      serializeSeq(obj.complaints, ComplaintSerializer)
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup] = None): Try[R3Data] = Try{
    implicit val group: DiscreteLogGroup = decoder.get

    val senderID = Ints.fromByteArray(bytes.slice(0, Ints.BYTES))

    val complaints = parseSeq(
      bytes.slice(Ints.BYTES, bytes.length),
      ComplaintSerializer
    ).get._1

    R3Data(senderID, complaints)
  }
}
