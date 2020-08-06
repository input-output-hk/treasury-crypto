package io.iohk.protocol.voting.approval.multi_delegation

import com.google.common.primitives.Bytes
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.multi_delegation.MultiDelegBallot.MultiDelegBallotTypes

import scala.util.Try


trait MultiDelegBallot extends BytesSerializable {

  override type DECODER = DiscreteLogGroup

  def proposalId: Int
  def ballotTypeId: Byte

  def verifyBallot(pctx: ApprovalContext, pubKey: PubKey): Boolean
}

object MultiDelegBallot {
  object MultiDelegBallotTypes extends Enumeration {
    val Voter, Expert, PrivateVoter = Value
  }
}

object MultiDelegBallotSerializer extends Serializer[MultiDelegBallot, DiscreteLogGroup] {
  override def toBytes(b: MultiDelegBallot): Array[Byte] = b match {
    case v: MultiDelegPublicStakeBallot => Bytes.concat(Array(v.ballotTypeId), MultiDelegPublicStakeBallotSerializer.toBytes(v))
    case e: MultiDelegExpertBallot => Bytes.concat(Array(e.ballotTypeId), MultiDelegExpertBallotSerializer.toBytes(e))
    case pv: MultiDelegPrivateStakeBallot => Bytes.concat(Array(pv.ballotTypeId), MultiDelegPrivateStakeBallotSerializer.toBytes(pv))
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[MultiDelegBallot] = Try {
    val ballotTypeId = bytes(0).toInt
    MultiDelegBallotTypes(ballotTypeId) match {
      case MultiDelegBallotTypes.Voter => MultiDelegPublicStakeBallotSerializer.parseBytes(bytes.drop(1), decoder).get
      case MultiDelegBallotTypes.Expert => MultiDelegExpertBallotSerializer.parseBytes(bytes.drop(1), decoder).get
      case MultiDelegBallotTypes.PrivateVoter => MultiDelegPrivateStakeBallotSerializer.parseBytes(bytes.drop(1), decoder).get
    }
  }
}