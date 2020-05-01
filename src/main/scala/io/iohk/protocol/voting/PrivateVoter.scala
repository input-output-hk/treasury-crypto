package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.nizk.shvzk.SHVZKGen
import io.iohk.protocol.nizk.unitvectornizk.MultRelationNIZK
import io.iohk.protocol.voting.ballots.{PrivateVoterBallot, VoterBallot}

import scala.util.Try

class PrivateVoter (override val ctx: CryptoContext,
                    val expertsNum: Int,
                    val publicKey: PubKey,
                    val stake: BigInt) extends Voter(ctx) {

  /**
    *
    * @param proposalID
    * @param choice either VotingOptions (in case a voter votes directly) or expert id (in case delegation)
    * @param withProof
    * @return
    */
  def createBallot(proposalID: Int,
                   vote: Either[VotingOptions.Value, Int],
                   withProof: Boolean = true): Try[PrivateVoterBallot] = Try {

    val nonZeroPos = vote match {
      case Right(expertId) => {
        assert(expertId >= 0 && expertId < expertsNum)
        expertId
      }
      case Left(choice) => choice match {
        case VotingOptions.Yes      => expertsNum
        case VotingOptions.No       => expertsNum + 1
        case VotingOptions.Abstain  => expertsNum + 2
      }
    }

    val encryptedStake = LiftedElGamalEnc.encrypt(publicKey, stake).get._1

    // Step 1: building encrypted unit vector of voter's preference
    val (u, uRand) = buildUnitVector(expertsNum + VotingOptions.values.size, nonZeroPos)
    val (uDeleg, uChoice) = u.splitAt(expertsNum)
    val uVector = UnitVector(uDeleg, uChoice)
    val uProof =
      if (withProof)
        Some(new SHVZKGen(publicKey, u, nonZeroPos, uRand).produceNIZK().get)
      else None

    // Step 2: building a vector of (a^e_i)*Enc(0), where a is an encrypted stake and e_i is a corresponding bit of a unit vector
    val plainUnitVector = Array.fill(u.size)(0)
    plainUnitVector(nonZeroPos) = 1

    val vRand = Vector.fill(u.size)(group.createRandomNumber)
    val v = vRand.zip(plainUnitVector).map { case (r,bit) =>
      val st = encryptedStake.pow(bit).get
      val encryptedZero = LiftedElGamalEnc.encrypt(publicKey, r, 0).get
      st.multiply(encryptedZero).get
    }
    val vProof =
      if (withProof)
        Some(MultRelationNIZK.produceNIZK(publicKey, encryptedStake, plainUnitVector, uRand, vRand).get)
      else None
    val (vDeleg, vChoice) = v.splitAt(expertsNum)
    val vVector = UnitVector(vDeleg, vChoice)

    PrivateVoterBallot(proposalID, uVector, vVector, uProof, vProof, encryptedStake)
  }
}
