package io.iohk.protocol.tally

import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.nizk.ElgamalDecrNIZK
import io.iohk.protocol.tally.datastructures._
import io.iohk.protocol.voting.ballots.ExpertBallot
import io.iohk.protocol.{CryptoContext, Identifier}

import scala.util.{Success, Try}

object TallyPhases extends Enumeration {
  val Init, TallyR1, TallyR2, TallyR3, TallyR4 = Value
}

class TallyNew(ctx: CryptoContext,
               cmIdentifier: Identifier[Int],
               disqualifiedCommitteeMembers: Map[PubKey, PrivKey]) {
  import ctx.{group, hash}

  private var currentRound = TallyPhases.Init
  private val allCommitteeIds = cmIdentifier.pubKeys.map(cmIdentifier.getId(_).get).toSet
  private var disqualifiedCommitteeIds = disqualifiedCommitteeMembers.keySet.map(cmIdentifier.getId(_).get)
  private var delegationsSum = Option(None)


  def getCurrentPhase = currentRound

//  def recoverState(phase: TallyPhases.Value, storage: RoundsDataStorage)

  /**
    * Generates TallyR1Data that should be submitted by a committee member. It contains decryption shares for the
    * delegation part of the unit vector obtained by summing up all voters unit vectors.
    *
    * @param summator contains the result of summation of delegation parts of voter's encrypted unit vectors
    * @param committeeMemberKey key pair of a committee member that generates R1Data
    * @return
    */
  def generateR1Data(summator: BallotsSummator, committeeMemberKey: KeyPair): Try[TallyR1Data] = Try {
    val (privKey, pubKey) = committeeMemberKey
    val uvDelegationsSum = summator.getDelegationsSum

    val decryptionShares = uvDelegationsSum.map { case (proposalID,v) =>
      val decryptedC1Shares = v.map { unit =>
        val decryptedC1 = unit.c1.pow(privKey).get
        val proof = ElgamalDecrNIZK.produceNIZK(unit, privKey).get
        (decryptedC1, proof)
      }
      proposalID -> DecryptionShare(proposalID, decryptedC1Shares.toSeq)
    }

    val committeeId = cmIdentifier.getId(pubKey).get
    TallyR1Data(committeeId, decryptionShares)
  }

  /**
    *
    * @param summator
    * @param committePubKey
    * @param r1Data
    * @return Try[Success] if r1Data is valid
    */
  def verifyRound1Data(summator: BallotsSummator, committePubKey: PubKey, r1Data: TallyR1Data): Try[Unit] = Try {
    val uvDelegationsSum = summator.getDelegationsSum
    val proposalIds = uvDelegationsSum.keySet
    val committeID = cmIdentifier.getId(committePubKey).get

    require(r1Data.issuerID == committeID, "Committee identifier in R1Data is invalid")
    require(!disqualifiedCommitteeIds.contains(r1Data.issuerID), "Committee member was disqualified")
    require(r1Data.decryptionShares.keySet.equals(proposalIds), "Not all decryption shares are provided")

    r1Data.decryptionShares.foreach { case (proposalId, s) =>
      require(proposalId == s.proposalId)
      require(s.validate(ctx, committePubKey, uvDelegationsSum(proposalId)).isSuccess, "Invalid decryption share")
    }
  }

  /**
    * executeRound1 should be called after all committee members submitted their TallyR1Data. It updates the tally state.
    * It is assumed that the data in r1DataAll has already been verified.
    *
    * @param summator
    * @param r1DataAll
    * @return
    */
  def executeRound1(summator: BallotsSummator, r1DataAll: Seq[TallyR1Data]): Try[TallyNew] = Try {
    val submittedCommitteeIds = r1DataAll.map(_.issuerID).toSet
    require(submittedCommitteeIds.size == r1DataAll.size, "There is a TallyR1Data from the same committee member")

    val expectedCommitteeIds = allCommitteeIds.diff(disqualifiedCommitteeIds)
    val failedCommitteeIds = expectedCommitteeIds.diff(submittedCommitteeIds)

    //TODO: maybe compute decryptionSharesSum
    this
  }

  /**
    * In the case some committee members haven't submitted decryption shares on Tally Round 1, they are considered
    * failed and all other committee members should jointly reconstruct thier key. At Round 2, each qualified committee
    * member submits his share of a secret key of a failed committee member (for all failed CMs).
    *
    * @param committePrivateKey
    * @param dkgR1Data
    * @return
    */
  def generateR2Data(committePrivateKey: PrivKey, dkgR1Data: Seq[R1Data]): Try[TallyR2Data] = ???
  def verifyRound2Data(committePubKey: PubKey, r2Data: TallyR2Data): Boolean = ???

  /**
    * At the end of the Round 2, all decryption shares should be available and, thus, the delegations can be decrypted.
    * Given that delegations are available we can sum up all the experts ballot weighted by delegated voting power.
    *
    * @param r2DataAll
    * @param expertBallots
    * @return
    */
  def executeRound2(r2DataAll: Seq[TallyR2Data], expertBallots: Seq[ExpertBallot]): Try[Unit] = ???

  def generateR3Data(committePrivateKey: PrivKey): Try[TallyR3Data] = ???
  def verifyRound3Data(committePubKey: PubKey, r3Data: TallyR3Data): Boolean = ???
  def executeRound3(r3DataAll: Seq[TallyR1Data]): Try[TallyR1Data] = ???

  def generateR4Data(committePrivateKey: PrivKey): Try[TallyR4Data] = ???
  def verifyRound4Data(committePubKey: PubKey, r4Data: TallyR4Data): Boolean = ???
  def executeRound4(r4DataAll: Seq[TallyR4Data]): Try[TallyR4Data] = ???
}

object TallyNew {
  type Delegations = Seq[BigInt] // a sequence with the number of delegated coins to each expert
}