package io.iohk.protocol.resharing.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize
import io.iohk.protocol.common.utils.Serialization.{parseSeq, serializeSeq}

import scala.util.Try

// senderID - is an ID of the dealer who distributes the shares (in SharedShare) of it's own shares
case class ResharingData(senderID: Int, sharedShares: Seq[SharedShare])
  extends BytesSerializable with HasSize {

  override type M = ResharingData
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = ResharingDataSerializer

  def size: Int = bytes.length
}

object ResharingDataSerializer extends Serializer[ResharingData, DiscreteLogGroup]{
  def toBytes(obj: ResharingData): Array[Byte] = {
    Bytes.concat(
      Ints.toByteArray(obj.senderID),
      serializeSeq(obj.sharedShares, SharedShareSerializer)
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[ResharingData] = Try{
    implicit val group: DiscreteLogGroup = decoder.get

    val (senderID, sharedSharesOffset) = (Ints.fromByteArray(bytes.slice(0, Ints.BYTES)), Ints.BYTES)

    val (sharedShares, _) = parseSeq(
      bytes.slice(sharedSharesOffset, bytes.length),
      SharedShareSerializer
    ).get

    ResharingData(senderID, sharedShares)
  }
}
