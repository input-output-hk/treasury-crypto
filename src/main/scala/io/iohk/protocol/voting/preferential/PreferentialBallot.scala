package io.iohk.protocol.voting.preferential

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.voting.preferential.PreferentialBallot.PreferentialBallotTypes

import scala.util.Try

trait PreferentialBallot extends BytesSerializable {
  override type DECODER = DiscreteLogGroup

  def ballotTypeId: Byte

  def verifyBallot(pctx: PreferentialContext, pubKey: PubKey): Boolean
}

object PreferentialBallot {
  object PreferentialBallotTypes extends Enumeration {
    val Voter, Expert = Value
  }
}

object PreferentialBallotSerializer extends Serializer[PreferentialBallot, DiscreteLogGroup] {
  override def toBytes(b: PreferentialBallot): Array[Byte] =
    ???

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[PreferentialBallot] = Try {
    val ballotTypeId = bytes(0).toInt
    PreferentialBallotTypes(ballotTypeId) match {
      case PreferentialBallotTypes.Voter => ???
      case PreferentialBallotTypes.Expert => ???
    }
  }
}