package io.iohk.protocol.keygen.datastructures.round5_1

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.Serializer
import io.iohk.protocol.keygen.Share
import io.iohk.protocol.keygen.datastructures.round4.OpenedShare

import scala.util.Try

/**
  * This is just a wrapper for ViolatorsSharesData
  *
  * @param issuerID
  * @param violatorsShares
  */
case class R5_1Data(override val issuerID: Int,
                    override val violatorsShares: Seq[Share]
                   ) extends ViolatorsSharesData(issuerID, violatorsShares)

object R5_1DataSerializer extends Serializer[R5_1Data, DiscreteLogGroup] {
  override def toBytes(obj: R5_1Data): Array[Byte] = ViolatorsSharesDataSerializer.toBytes(obj)

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[R5_1Data] = Try {
    val s = ViolatorsSharesDataSerializer.parseBytes(bytes, decoder).get
    R5_1Data(s.issuerID, s.violatorsShares)
  }
}