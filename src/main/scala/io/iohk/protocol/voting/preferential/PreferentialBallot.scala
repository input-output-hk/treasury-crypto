package io.iohk.protocol.voting.preferential

import com.google.common.primitives.Bytes
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.nizk.shvzk.SHVZKProof
import io.iohk.protocol.voting.{ExpertBallot, ExpertBallotSerializer, PrivateStakeBallot, PrivateVoterBallotSerializer, PublicStakeBallot, PublicStakeBallotSerializer}
import io.iohk.protocol.voting.preferential.PreferentialBallot.PreferentialBallotTypes

import scala.util.Try

trait PreferentialBallot extends BytesSerializable {
  override type DECODER = DiscreteLogGroup

  def ballotTypeId: Byte

  def verifyBallot(pctx: PreferentialContext, pubKey: PubKey): Boolean
}

case class RankVector(rank: Vector[ElGamalCiphertext], z: ElGamalCiphertext, proof: Option[SHVZKProof])

object PreferentialBallot {
  object PreferentialBallotTypes extends Enumeration {
    val Voter, Expert = Value
  }
}

object PreferentialBallotSerializer extends Serializer[PreferentialBallot, DiscreteLogGroup] {
  override def toBytes(b: PreferentialBallot): Array[Byte] = b match {
    case v: PreferentialVoterBallot => ??? //Bytes.concat(Array(v.ballotTypeId), PreferentialVoterBallotSerializer.toBytes(v))
    case e: PreferentialExpertBallot => Bytes.concat(Array(e.ballotTypeId), PreferentialExpertBallotSerializer.toBytes(e))
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[PreferentialBallot] = {
    val ballotTypeId = bytes(0).toInt
    PreferentialBallotTypes(ballotTypeId) match {
      case PreferentialBallotTypes.Voter => ???
      case PreferentialBallotTypes.Expert => PreferentialExpertBallotSerializer.parseBytes(bytes.drop(1), decoder)
    }
  }
}