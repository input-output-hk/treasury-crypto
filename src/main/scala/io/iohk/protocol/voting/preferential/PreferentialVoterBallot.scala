package io.iohk.protocol.voting.preferential

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, ElGamalCiphertextSerializer, LiftedElGamalEnc}
import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.Serializer
import io.iohk.protocol.nizk.shvzk.{SHVZKGen, SHVZKProof, SHVZKProofSerializer, SHVZKVerifier}
import io.iohk.protocol.nizk.unitvectornizk.{AllOneNIZK, AllOneNIZKProof, AllOneNIZKProofSerializer}
import io.iohk.protocol.voting.buildEncryptedUnitVector
import io.iohk.protocol.voting.preferential.PreferentialBallot.PreferentialBallotTypes

import scala.util.Try


case class PreferentialVoterBallot(delegVector: Vector[ElGamalCiphertext],
                                   delegVectorProof: Option[SHVZKProof],
                                   rankVectors: List[RankVector],
                                   rankVectorsProof: Option[AllOneNIZKProof],
                                   w: Option[ElGamalCiphertext],
                                   stake: BigInt
                                  ) extends PreferentialBallot {
  override type M = PreferentialBallot
  override val serializer = PreferentialBallotSerializer

  override val ballotTypeId: Byte = PreferentialBallotTypes.Voter.id.toByte


  def weightedDelegationVector(implicit group: DiscreteLogGroup): Vector[ElGamalCiphertext] = {
    delegVector.map(v => v.pow(stake).get)
  }

  def weightedRankVectors(implicit group: DiscreteLogGroup): List[Vector[ElGamalCiphertext]] = {
    rankVectors.map(rv => rv.rank.map(v => v.pow(stake).get))
  }

  override def verifyBallot(pctx: PreferentialContext, pubKey: PubKey): Boolean = Try {
    import pctx.cryptoContext.{group, hash}

    require(stake >= 0)
    require(delegVector.size == pctx.numberOfExperts)
    val neg_w =
      if (pctx.numberOfExperts > 0) {
        require(new SHVZKVerifier(pubKey, w.get +: delegVector, delegVectorProof.get).verifyProof())
        val one = LiftedElGamalEnc.encrypt(pubKey, 1, 1).get
        Vector(one / w.get)
      } else Vector()

    require(rankVectors.size == pctx.numberOfProposals)
    rankVectors.foreach { rv =>
      require(rv.rank.size == pctx.numberOfRankedProposals)
      val v = neg_w ++ (rv.z +: rv.rank)
      require(new SHVZKVerifier(pubKey, v, rv.proof.get).verifyProof())
    }

    val neg_w_init = neg_w.headOption.getOrElse(ElGamalCiphertext(group.groupIdentity, group.groupIdentity))
    val neg_w_vec = Vector.fill(pctx.numberOfRankedProposals)(neg_w_init)
    val rankVectorsSum = rankVectors.foldLeft(neg_w_vec) { (acc, rv) =>
      acc.zip(rv.rank).map(x => x._1.multiply(x._2).get)
    }
    require(AllOneNIZK.verifyNIZK(pubKey, rankVectorsSum, rankVectorsProof.get))

  }.isSuccess
}

object PreferentialVoterBallot {

  def createBallot(pctx: PreferentialContext,
                   vote: PreferentialVote,
                   ballotEncryptionKey: PubKey,
                   stake: BigInt,
                   withProof: Boolean = true): Try[PreferentialVoterBallot] = Try {
    import pctx.cryptoContext.{group, hash}

    def prepareRankVectorsWithProof(ranking: Option[List[Int]], w: Option[ElGamalCiphertext], w_rand: Option[Randomness]) = {
      import pctx.cryptoContext.{group, hash}

      val one = LiftedElGamalEnc.encrypt(ballotEncryptionKey, 1, 1).get
      val neg_w = w.map(w => Vector(one / w)).getOrElse(Vector())
      val neg_w_rand = w_rand.map(w_rand => Vector(1 - w_rand)).getOrElse(Vector())

      val neutralCiphertext = ElGamalCiphertext(group.groupIdentity, group.groupIdentity)
      var rankVectorsSum = Vector.fill(pctx.numberOfRankedProposals)(neg_w.headOption.getOrElse(neutralCiphertext))
      var randomnessSum = Vector.fill(pctx.numberOfRankedProposals)(neg_w_rand.headOption.getOrElse(BigInt(0)))

      val rankVectors = (0 until pctx.numberOfProposals).map { proposalId =>
        val nonZeroPos = ranking match {
          case Some(ranking) => ranking.indexOf(proposalId) match {
            case -1 => 0 // there is no rank for proposal, in this case set z=1 and all other zeros. z bit is the first bit in vector
            case x => x + 1 // in case proposal is ranked, set corresponding bit to '1'
          }
          case None => -1
        }
        val (vector, rand) =
          buildEncryptedUnitVector(size = pctx.numberOfRankedProposals + 1, nonZeroPos, ballotEncryptionKey)
        val proof = withProof match {
          case true =>
            rankVectorsSum = rankVectorsSum.zip(vector.tail).map(x => x._1.multiply(x._2).get) // sum up vectors without z bit
            randomnessSum = randomnessSum.zip(rand.tail).map(x => x._1 + x._2)
            Some(new SHVZKGen(ballotEncryptionKey, neg_w ++ vector, nonZeroPos + neg_w.size, neg_w_rand ++ rand).produceNIZK().get)
          case _ => None
        }
        RankVector(vector.tail, vector.head, proof)
      }.toList

      // rankVectorsProof proves that the sum of rank vectors is the vector of "1". This proof is generated only
      val rankVectorsProof = if (withProof)
        Some(AllOneNIZK.produceNIZK(ballotEncryptionKey, rankVectorsSum.zip(randomnessSum)).get)
        else None
      (rankVectors, rankVectorsProof)
    }

    def prepareDelegationVectorWithProof(expertId: Option[Int]) = {
      if (pctx.numberOfExperts <= 0)
        (None, None, Vector(), None)
      else {
        val nonZeroBitPosition = expertId.map(_ + 1).getOrElse(0)
        val (vector, rand) =
          buildEncryptedUnitVector(size = pctx.numberOfExperts + 1, nonZeroBitPosition, ballotEncryptionKey)
        val proof = withProof match {
          case true => Some(new SHVZKGen(ballotEncryptionKey, vector, nonZeroBitPosition, rand).produceNIZK().get)
          case _ => None
        }
        (Some(vector.head), Some(rand.head), vector.tail, proof)
      }
    }

    require(stake > 0)
    require(vote.validate(pctx))

    vote match {
      case DirectPreferentialVote(ranking) =>
        val (w, w_rand, delegVector, delegVectorProof) = prepareDelegationVectorWithProof(None)
        val (rankVectors, proof) = prepareRankVectorsWithProof(Some(ranking), w, w_rand)
        PreferentialVoterBallot(delegVector, delegVectorProof, rankVectors, proof, w, stake)
      case DelegatedPreferentialVote(expertId) =>
        val (w, w_rand, delegVector, delegVectorProof) = prepareDelegationVectorWithProof(Some(expertId))
        val (rankVectors, proof) = prepareRankVectorsWithProof(None, w, w_rand)
        PreferentialVoterBallot(delegVector, delegVectorProof, rankVectors, proof, w, stake)
    }
  }
}

/* PreferentialBallotSerializer should be used to deserialize PreferentialVoterBallot */
private[voting] object PreferentialVoterBallotSerializer extends Serializer[PreferentialVoterBallot, DiscreteLogGroup] {

  override def toBytes(ballot: PreferentialVoterBallot): Array[Byte] = {
    val rankVectorsBytes = ballot.rankVectors.foldLeft(Array[Byte]()) { (acc, v) =>
      val vectorBytes = (v.z +: v.rank).foldLeft(Array[Byte]()) { (acc2, b) =>
        val bytes = b.bytes
        Bytes.concat(acc2, Array(bytes.length.toByte), bytes)
      }
      val proofBytes = v.proof match {
        case Some(p) => p.bytes
        case None => Array[Byte]()
      }
      Bytes.concat(acc,
        Shorts.toByteArray((v.rank.length+1).toShort), vectorBytes,
        Ints.toByteArray(proofBytes.length), proofBytes)
    }

    val rankVectorsProofBytes = ballot.rankVectorsProof.map(_.bytes).getOrElse(Array[Byte]())

    val delegVectorBytes = ballot.delegVector.foldLeft(Array[Byte]()) { (acc, b) =>
      val bytes = b.bytes
      Bytes.concat(acc, Array(bytes.length.toByte), bytes)
    }
    val delegProofBytes = ballot.delegVectorProof match {
      case Some(p) => p.bytes
      case None => Array[Byte]()
    }
    val wBytes = ballot.w.map(_.bytes).getOrElse(Array[Byte]())

    val stakeBytes = ballot.stake.toByteArray

    Bytes.concat(
      Shorts.toByteArray(ballot.delegVector.size.toShort), delegVectorBytes,
      Ints.toByteArray(delegProofBytes.size), delegProofBytes,
      Shorts.toByteArray(ballot.rankVectors.length.toShort), rankVectorsBytes,
      Shorts.toByteArray(rankVectorsProofBytes.size.toShort), rankVectorsProofBytes,
      Array(wBytes.length.toByte), wBytes,
      Array(stakeBytes.length.toByte), stakeBytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[PreferentialVoterBallot] = Try {
    val delegVectorLen = Shorts.fromByteArray(bytes.slice(0,2))
    var position = 2

    val delegVector = (0 until delegVectorLen).map { _ =>
      val len = bytes(position)
      val c = ElGamalCiphertextSerializer.parseBytes(bytes.slice(position+1, position+1+len), decoder).get
      position = position + len + 1
      c
    }.toVector

    val delegVectorProofLen =  Ints.fromByteArray(bytes.slice(position,position+4))
    position += 4
    val delegVectorProof = delegVectorProofLen match {
      case 0 => None
      case l =>
        position = position + l
        Some(SHVZKProofSerializer.parseBytes(bytes.slice(position - l, position), decoder).get)
    }

    val rankVectorsLen = Shorts.fromByteArray(bytes.slice(position,position+2))
    position += 2

    val rankVectors = (0 until rankVectorsLen).map { _ =>
      val vectorLen = Shorts.fromByteArray(bytes.slice(position,position+2))
      position += 2
      val vector = (0 until vectorLen).map { _ =>
        val len = bytes(position)
        val c = ElGamalCiphertextSerializer.parseBytes(bytes.slice(position+1, position+1+len), decoder).get
        position = position + len + 1
        c
      }.toVector
      val proofLen = Ints.fromByteArray(bytes.slice(position,position+4))
      position += 4
      val proof = proofLen match {
        case 0 => None
        case l =>
          position = position + l
          Some(SHVZKProofSerializer.parseBytes(bytes.slice(position - l, position), decoder).get)
      }
      RankVector(vector.tail, vector.head, proof)
    }.toList

    val rankVectorsProofLen =  Shorts.fromByteArray(bytes.slice(position,position+2))
    position += 2
    val rankVectorsProof = rankVectorsProofLen match {
      case 0 => None
      case l =>
        position = position + l
        Some(AllOneNIZKProofSerializer.parseBytes(bytes.slice(position - l, position), decoder).get)
    }

    val wLen = bytes(position)
    position += 1
    val w = wLen match {
      case 0 => None
      case l =>
        position += wLen
        Some(ElGamalCiphertextSerializer.parseBytes(bytes.slice(position - wLen, position), decoder).get)
    }

    val stakeLen = bytes(position)
    val stake = BigInt(bytes.slice(position+1, position+1+stakeLen))

    PreferentialVoterBallot(delegVector, delegVectorProof, rankVectors, rankVectorsProof, w, stake)
  }
}