package io.iohk.protocol.voting.approval.multi_delegation

import com.google.common.primitives.Bytes
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.multi_delegation.MultiDelegBallot.BallotTypes

import scala.util.Try


trait MultiDelegBallot extends BytesSerializable {

  override type DECODER = DiscreteLogGroup

  def ballotTypeId: Byte
  def proposalId: Int

  def verifyBallot(pctx: ApprovalContext, pubKey: PubKey): Try[Unit]
}

object MultiDelegBallot {
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

object MultiDelegBallotSerializer extends Serializer[MultiDelegBallot, DiscreteLogGroup] {
  override def toBytes(b: MultiDelegBallot): Array[Byte] = b match {
    case v: MultiDelegPublicStakeBallot => Bytes.concat(Array(v.ballotTypeId), MultiDelegPublicStakeBallotSerializer.toBytes(v))
    case e: MultiDelegExpertBallot => Bytes.concat(Array(e.ballotTypeId), MultiDelegExpertBallotSerializer.toBytes(e))
    case pv: MultiDelegPrivateStakeBallot => Bytes.concat(Array(pv.ballotTypeId), MultiDelegPrivateStakeBallotSerializer.toBytes(pv))
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[MultiDelegBallot] = Try {
    val ballotTypeId = bytes(0).toInt
    BallotTypes(ballotTypeId) match {
      case BallotTypes.Voter => MultiDelegPublicStakeBallotSerializer.parseBytes(bytes.drop(1), decoder).get
      case BallotTypes.Expert => MultiDelegExpertBallotSerializer.parseBytes(bytes.drop(1), decoder).get
      case BallotTypes.PrivateVoter => MultiDelegPrivateStakeBallotSerializer.parseBytes(bytes.drop(1), decoder).get
    }
  }
}