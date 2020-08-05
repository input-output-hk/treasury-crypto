package io.iohk.protocol.voting.approval.multi_delegation

import com.google.common.primitives.Bytes
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.multi_delegation.Ballot.BallotTypes

import scala.util.Try


trait Ballot extends BytesSerializable {

  override type DECODER = DiscreteLogGroup

  def ballotTypeId: Byte
  def proposalId: Int

  def verifyBallot(pctx: ApprovalContext, pubKey: PubKey): Try[Unit]
}

object Ballot {
  object BallotTypes extends Enumeration {
    val Voter, Expert, PrivateVoter = Value
  }

  def buildEncryptedUnitVector(size: Int, nonZeroPos: Int, key: PubKey)
                              (implicit group: DiscreteLogGroup)
  : (Vector[ElGamalCiphertext], Vector[Randomness]) = {
    val randomness = Vector.fill(size)(group.createRandomNumber)
    val ciphertexts = randomness.zipWithIndex.map { case (r, i) =>
      LiftedElGamalEnc.encrypt(key, r, if (i == nonZeroPos) 1 else 0).get
    }
    (ciphertexts, randomness)
  }
}

object BallotSerializer extends Serializer[Ballot, DiscreteLogGroup] {
  override def toBytes(b: Ballot): Array[Byte] = b match {
    case v: PublicStakeBallot => Bytes.concat(Array(v.ballotTypeId), PublicStakeBallotSerializer.toBytes(v))
    case e: ExpertBallot => Bytes.concat(Array(e.ballotTypeId), ExpertBallotSerializer.toBytes(e))
    case pv: PrivateStakeBallot => Bytes.concat(Array(pv.ballotTypeId), PrivateVoterBallotSerializer.toBytes(pv))
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[Ballot] = Try {
    val ballotTypeId = bytes(0).toInt
    BallotTypes(ballotTypeId) match {
      case BallotTypes.Voter => PublicStakeBallotSerializer.parseBytes(bytes.drop(1), decoder).get
      case BallotTypes.Expert => ExpertBallotSerializer.parseBytes(bytes.drop(1), decoder).get
      case BallotTypes.PrivateVoter => PrivateVoterBallotSerializer.parseBytes(bytes.drop(1), decoder).get
    }
  }
}