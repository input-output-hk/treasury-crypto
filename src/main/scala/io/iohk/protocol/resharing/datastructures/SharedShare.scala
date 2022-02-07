package io.iohk.protocol.resharing.datastructures

import com.google.common.primitives.{Bytes, Ints}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.core.utils.HasSize
import io.iohk.protocol.common.datastructures.{SecretShare, SecretShareSerializer}
import io.iohk.protocol.common.utils.GroupElementSerializer
import io.iohk.protocol.common.utils.Serialization.{parseSeq, serializeSeq}

import scala.util.Try

// Doesn't contain an evaluation point of the initial share, to avoid it's duplication for multiple resharings;
// The evaluation point should be computed from a dealer's ID (it is assumed to be in the structure which aggregates the SharedShares)
case class SharedShare(encShares: Seq[SecretShare], // encrypted shares of the initial share
                       coeffsCommitments: Seq[GroupElement]) // g^coeff commitments of coefficients of the polynomial which was used for shares creation
  extends BytesSerializable with HasSize {

  override type M = SharedShare
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = SharedShareSerializer

  def size: Int = bytes.length
}

object SharedShareSerializer extends Serializer[SharedShare, DiscreteLogGroup]{
  def toBytes(obj: SharedShare): Array[Byte] = {
    Bytes.concat(
      serializeSeq(obj.encShares, SecretShareSerializer),
      serializeSeq(obj.coeffsCommitments, GroupElementSerializer)
    )
  }

  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[SharedShare] = Try{
    implicit val group: DiscreteLogGroup = decoder.get

    val (encShares, coeffsCommitmentsOffset) = parseSeq(
      bytes.slice(0, bytes.length),
      SecretShareSerializer
    ).get

    val (coeffsCommitments, _) = parseSeq(
      bytes.slice(coeffsCommitmentsOffset, bytes.length),
      GroupElementSerializer
    ).get

    SharedShare(encShares, coeffsCommitments)
  }
}


//import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
//import io.iohk.core.serialization.{BytesSerializable, Serializer}
//import io.iohk.core.utils.HasSize
//
//import scala.util.Try
//
//case class _
//extends BytesSerializable  with HasSize {
//  override type M = _
//  override type DECODER = DiscreteLogGroup
//  override val serializer: Serializer[M, DECODER] = _Serializer
//  def size: Int = bytes.length
//}
//
//object _Serializer extends Serializer[_, DiscreteLogGroup]{
//  def toBytes(obj: _): Array[Byte] = {
//
//  }
//
//  def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[_] = Try{
//
//  }
//}