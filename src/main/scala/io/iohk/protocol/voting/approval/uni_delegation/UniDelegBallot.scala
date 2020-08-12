package io.iohk.protocol.voting.approval.uni_delegation

import com.google.common.primitives.Bytes
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.uni_delegation.UniDelegBallot.UniBallotTypes

import scala.util.Try

trait UniDelegBallot extends BytesSerializable {

  override type DECODER = DiscreteLogGroup

  def ballotTypeId: Byte
  def verifyBallot(pctx: ApprovalContext, pubKey: PubKey): Boolean
}

object UniDelegBallot {
  object UniBallotTypes extends Enumeration {
    val Voter, Expert, PrivateVoter = Value
  }
}

object UniDelegBallotSerializer extends Serializer[UniDelegBallot, DiscreteLogGroup] {
  override def toBytes(b: UniDelegBallot): Array[Byte] = b match {
    case v: UniDelegPublicStakeBallot => Bytes.concat(Array(v.ballotTypeId), UniDelegPublicStakeBallotSerializer.toBytes(v))
    case e: UniDelegExpertBallot => Bytes.concat(Array(e.ballotTypeId), UniDelegExpertBallotSerializer.toBytes(e))
    //case pv: UniDelegPrivateStakeBallot => Bytes.concat(Array(pv.ballotTypeId), UniDelegPrivateStakeBallotSerializer.toBytes(pv))
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[UniDelegBallot] = Try {
    val ballotTypeId = bytes(0).toInt
    UniBallotTypes(ballotTypeId) match {
      case UniBallotTypes.Voter => UniDelegPublicStakeBallotSerializer.parseBytes(bytes.drop(1), decoder).get
      case UniBallotTypes.Expert => UniDelegExpertBallotSerializer.parseBytes(bytes.drop(1), decoder).get
      //case UniBallotTypes.PrivateVoter => UniDelegPrivateStakeBallotSerializer.parseBytes(bytes.drop(1), decoder).get
    }
  }
}