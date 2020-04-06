package io.iohk.protocol.tally.datastructures

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.Serializer
import io.iohk.protocol.keygen.datastructures.round4.OpenedShare
import io.iohk.protocol.keygen.datastructures.round5_1.{R5_1Data, ViolatorsSharesData, ViolatorsSharesDataSerializer}

import scala.util.Try

/**
  * This is a wrapper for the ViolatorsSharesData. Tally Round 2 is actually
  * the same as DKG Round 5_1, so it uses the same data structure.
  *
  * @param issuerID
  * @param violatorsShares
  */
case class TallyR2Data(override val issuerID:        Int,
                       override val violatorsShares: Array[(Int, OpenedShare)]
                      ) extends ViolatorsSharesData(issuerID, violatorsShares)


object TallyR2DataSerializer extends Serializer[TallyR2Data, DiscreteLogGroup] {

  override def toBytes(obj: TallyR2Data): Array[Byte] = ViolatorsSharesDataSerializer.toBytes(obj)

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[TallyR2Data] = Try {
    val s = ViolatorsSharesDataSerializer.parseBytes(bytes, decoder).get
    TallyR2Data(s.issuerID, s.violatorsShares)
  }
}
