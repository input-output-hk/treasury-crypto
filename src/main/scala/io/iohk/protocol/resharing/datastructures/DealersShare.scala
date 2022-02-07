package io.iohk.protocol.resharing.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.common.utils.BigIntSerializer

import scala.util.Try

case class DealersShare(dealerID: Int,       // ID of the party who created the share
                        openedShare: BigInt) // value of the share
  extends BytesSerializable {
  override type M = DealersShare
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = DealersShareSerializer

  def isValid: Boolean = { true }
}

object DealersShareSerializer extends Serializer[DealersShare, DiscreteLogGroup]{
  def toBytes(obj: DealersShare): Array[Byte] = {
    val openedShare_bytes = BigIntSerializer.toBytes(obj.openedShare)

    Bytes.concat(
      Ints.toByteArray(obj.dealerID),
      Ints.toByteArray(openedShare_bytes.length),
      openedShare_bytes
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup] = None): Try[DealersShare] = Try{
    val dealerID = Ints.fromByteArray(bytes.slice(0, 4))

    val openedShare_bytes_len = Ints.fromByteArray(bytes.slice(4, 8))
    val openedShare_bytes = bytes.slice(8, 8 + openedShare_bytes_len)

    val openedShare = BigIntSerializer.parseBytes(openedShare_bytes).get

    DealersShare(dealerID, openedShare)
  }
}
