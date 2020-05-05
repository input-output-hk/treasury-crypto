package io.iohk.protocol.voting

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.Serializer
import io.iohk.protocol.ProtocolContext
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKProof, SHVZKProofSerializer, SHVZKVerifier}
import io.iohk.protocol.voting.Ballot.BallotTypes

import scala.util.Try

case class ExpertBallot(
  override val proposalId: Int,
  expertId: Int,
  uChoiceVector: Vector[ElGamalCiphertext],
  uProof: Option[SHVZKProof]
) extends Ballot {

  override type M = Ballot
  override val serializer = BallotSerializer

  override val ballotTypeId: Byte = BallotTypes.Expert.id.toByte

  override def verifyBallot(pctx: ProtocolContext, pubKey: PubKey): Try[Unit] = Try {
    import pctx.cryptoContext.{group, hash}
    require(uChoiceVector.size == pctx.numberOfChoices)
    require(expertId >= 0 && expertId < pctx.numberOfExperts)
    require(new SHVZKVerifier(pubKey, uChoiceVector, uProof.get).verifyProof())
  }
}

object ExpertBallot {

  def createBallot(pctx: ProtocolContext,
                   proposalID: Int,
                   expertID: Int,
                   vote: Int,
                   ballotEncryptionKey: PubKey,
                   withProof: Boolean = true): Try[ExpertBallot] = Try {
    import pctx.cryptoContext.{group, hash}
    require(vote >= 0 && vote < pctx.numberOfChoices, "Invalid vote!")
    require(expertID >= 0 && expertID < pctx.numberOfExperts, "Invalid expert ID!")

    val (uVector, uRand) = Ballot.buildEncryptedUnitVector(pctx.numberOfChoices, vote, ballotEncryptionKey)
    val uProof = withProof match {
      case true => Some(new SHVZKGen(ballotEncryptionKey, uVector, vote, uRand).produceNIZK().get)
      case _ => None
    }

    ExpertBallot(proposalID, expertID, uVector, uProof)
  }
}

/* BallotSerializer should be used to deserialize ExpertBallot */
private[voting] object ExpertBallotSerializer extends Serializer[ExpertBallot, DiscreteLogGroup] {
  override def toBytes(b: ExpertBallot): Array[Byte] = {
    val uvBytes = b.uChoiceVector.foldLeft(Array[Byte]()) { (acc, b) =>
      val bytes = b.bytes
      Bytes.concat(acc, Array(bytes.length.toByte), bytes)
    }
    val proofBytes = b.uProof.map(_.bytes).getOrElse(Array[Byte]())

    Bytes.concat(
      Ints.toByteArray(b.proposalId),
      Ints.toByteArray(b.expertId),
      Shorts.toByteArray(b.uChoiceVector.length.toShort), uvBytes,
      Ints.toByteArray(proofBytes.length), proofBytes,
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[ExpertBallot] = Try {
    val proposalId = Ints.fromByteArray(bytes.slice(0,4))
    val expertId = Ints.fromByteArray(bytes.slice(4,8))
    val vectorLen = Shorts.fromByteArray(bytes.slice(8,10))
    var position = 10

    val uvChoice: Vector[ElGamalCiphertext] = (0 until vectorLen).map { _ =>
      val len = bytes(position)
      val c = ElGamalCiphertextSerializer.parseBytes(bytes.slice(position+1, position+1+len), decoder).get
      position = position + len + 1
      c
    }.toVector

    val proofLen = Ints.fromByteArray(bytes.slice(position, position+4))
    position += 4
    val proof = proofLen match {
      case 0 => None
      case _ => {
        position += proofLen
        Some(SHVZKProofSerializer.parseBytes(bytes.slice(position-proofLen, position), decoder).get)
      }
    }

    ExpertBallot(proposalId, expertId, uvChoice, proof)
  }
}
