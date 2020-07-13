package io.iohk.protocol.voting.preferential

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.protocol.nizk.shvzk.{SHVZKProof, SHVZKVerifier}
import io.iohk.protocol.voting.preferential.PreferentialBallot.PreferentialBallotTypes

import scala.util.Try


case class PreferentialVoterBallot(delegVector: Vector[ElGamalCiphertext],
                                   rankVectors: List[Vector[ElGamalCiphertext]],
                                   w: ElGamalCiphertext,
                                   delegVectorProof: Option[SHVZKProof],
                                   rankVectorsProofs: Option[List[SHVZKProof]],
                                   stake: BigInt
                                  ) extends PreferentialBallot(rankVectors, rankVectorsProofs) {
  override type M = PreferentialBallot
  override val serializer = PreferentialBallotSerializer

  override val ballotTypeId: Byte = PreferentialBallotTypes.Voter.id.toByte

//
//  def weightedUnitVector(implicit group: DiscreteLogGroup): EncryptedUnitVector = {
//    EncryptedUnitVector(
//      uVector.delegations.map(v => v.pow(stake).get),
//      uVector.choice.map(v => v.pow(stake).get)
//    )
//  }

  override def verifyBallot(pctx: PreferentialContext, pubKey: PubKey): Boolean = Try {
    import pctx.cryptoContext.{group, hash}
    require(super.verifyBallot(pctx, pubKey))

    require(stake >= 0)
    require(delegVector.size == pctx.numberOfExperts)
    require(new SHVZKVerifier(pubKey, delegVector :+ w, delegVectorProof.get).verifyProof())

    val one = LiftedElGamalEnc.encrypt(pubKey, 1, 1).get
    val neg_w = one / w

    rankVectors.indices.foreach { i =>
      val v = rankVectors(i) :+ neg_w
      val proof = rankVectorsProofs.get(i)
      require(new SHVZKVerifier(pubKey, v, proof).verifyProof())
    }
  }.isSuccess
}
