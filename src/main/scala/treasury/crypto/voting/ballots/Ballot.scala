package treasury.crypto.voting.ballots

import java.math.BigInteger

import com.google.common.primitives.{Bytes, Ints, Shorts}
import treasury.crypto.core._
import treasury.crypto.core.primitives.dlog.DiscreteLogGroup
import treasury.crypto.core.serialization.{BytesSerializable, Serializer}
import treasury.crypto.nizk.shvzk.{SHVZKProof, SHVZKProofSerializer}
import treasury.crypto.voting._

import scala.util.Try

// The data structure for storing of the individual voter's/expert's choice
trait Ballot extends BytesSerializable {

  override type DECODER = DiscreteLogGroup

  def ballotTypeId: Byte

  def proposalId: Int
  def proof: SHVZKProof

  def unitVector: Array[Ciphertext]
}

object BallotCompanion extends Serializer[Ballot, DiscreteLogGroup] {
  override def toBytes(b: Ballot): Array[Byte] = b match {
    case v: VoterBallot => Bytes.concat(Array(v.ballotTypeId), VoterBallotCompanion.toBytes(v))
    case e: ExpertBallot => Bytes.concat(Array(e.ballotTypeId), ExpertBallotCompanion.toBytes(e))
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[Ballot] = Try {
    val ballotTypeId = bytes(0)
    ballotTypeId match {
      case id if id == VoterBallot.BallotTypeId => VoterBallotCompanion.parseBytes(bytes.drop(1), decoder).get
      case id if id == ExpertBallot.BallotTypeId => ExpertBallotCompanion.parseBytes(bytes.drop(1), decoder).get
    }
  }
}