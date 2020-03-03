package io.iohk.protocol.voting.ballots

import java.math.BigInteger

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core._
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.nizk.shvzk.{SHVZKProof, SHVZKProofSerializer}
import io.iohk.protocol.voting._

import scala.util.Try

// The data structure for storing of the individual voter's/expert's choice
trait Ballot extends BytesSerializable {

  override type DECODER = DiscreteLogGroup

  def ballotTypeId: Byte

  def proposalId: Int
  def proof: SHVZKProof

  def unitVector: Array[Ciphertext]
}

object BallotSerializer extends Serializer[Ballot, DiscreteLogGroup] {
  override def toBytes(b: Ballot): Array[Byte] = b match {
    case v: VoterBallot => Bytes.concat(Array(v.ballotTypeId), VoterBallotSerializer.toBytes(v))
    case e: ExpertBallot => Bytes.concat(Array(e.ballotTypeId), ExpertBallotSerializer.toBytes(e))
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[Ballot] = Try {
    val ballotTypeId = bytes(0)
    ballotTypeId match {
      case VoterBallot.BallotTypeId => VoterBallotSerializer.parseBytes(bytes.drop(1), decoder).get
      case ExpertBallot.BallotTypeId => ExpertBallotSerializer.parseBytes(bytes.drop(1), decoder).get
    }
  }
}