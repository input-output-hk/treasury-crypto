package io.iohk.protocol.resharing.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize
import io.iohk.protocol.common.utils.Serialization.{parseSeq, serializeSeq}

import scala.util.Try

case class ResharingComplaints(senderID: Int, complaints: Seq[IndexedComplaint])
  extends BytesSerializable with HasSize {
  override type M = ResharingComplaints
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = ResharingComplaintsSerializer
  def size: Int = bytes.length
}

object ResharingComplaintsSerializer extends Serializer[ResharingComplaints, DiscreteLogGroup]{
  def toBytes(obj: ResharingComplaints): Array[Byte] = {
    Bytes.concat(
      Ints.toByteArray(obj.senderID),
      serializeSeq(obj.complaints, IndexedComplaintSerializer)
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[ResharingComplaints] = Try{
    implicit val group: DiscreteLogGroup = decoder.get

    val (senderID, complaintsOffset) = (Ints.fromByteArray(bytes.slice(0, Ints.BYTES)), Ints.BYTES)

    val (complaints, _) = parseSeq(
      bytes.slice(complaintsOffset, bytes.length),
      IndexedComplaintSerializer
    ).get

    ResharingComplaints(senderID, complaints)
  }
}

case class IndexedComplaint(complaint: Complaint, index: Int)
  extends BytesSerializable with HasSize {
  override type M = IndexedComplaint
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = IndexedComplaintSerializer
  def size: Int = bytes.length
}

object IndexedComplaintSerializer extends Serializer[IndexedComplaint, DiscreteLogGroup]{
  def toBytes(obj: IndexedComplaint): Array[Byte] = {
    Bytes.concat(
      Ints.toByteArray(obj.index),
      obj.complaint.bytes
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[IndexedComplaint] = Try{
    val (index, complaintOffset) = (Ints.fromByteArray(bytes.slice(0, Ints.BYTES)), Ints.BYTES)
    val complaint = ComplaintSerializer.parseBytes(bytes.slice(complaintOffset, bytes.length), decoder).get

    IndexedComplaint(complaint, index)
  }
}