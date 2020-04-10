package io.iohk.protocol.tally

import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.core.crypto.primitives.dlog.GroupElement
import io.iohk.protocol.keygen.DistrKeyGen
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
               numberOfExperts: Int,
               disqualifiedAfterDKGCommitteeKeys: Map[PubKey, Option[PrivKey]]) {
  import ctx.{group, hash}

  private var currentRound = TallyPhases.Init
  def getCurrentRound = currentRound

  private val allCommitteeIds = cmIdentifier.pubKeys.map(cmIdentifier.getId(_).get).toSet
  private var disqualifiedBeforeTallyCommitteeIds = disqualifiedAfterDKGCommitteeKeys.keySet.map(cmIdentifier.getId(_).get)
  private var disqualifiedOnTallyR1CommitteeIds = Set[Int]()
  private var disqualifiedOnTallyR3CommitteeIds = Set[Int]()

  // here we will collect restored secret keys of committee members
  private var allDisqualifiedCommitteeKeys = disqualifiedAfterDKGCommitteeKeys.filter(_._2.isDefined).mapValues(_.get)

  private var delegationsSharesSum = Map[Int, Array[GroupElement]]()
  def getDelegationsSharesSum = delegationsSharesSum

  def getAllDisqualifiedCommitteeIds = disqualifiedBeforeTallyCommitteeIds ++ getDisqualifiedOnTallyCommitteeIds
  def getDisqualifiedOnTallyCommitteeIds = disqualifiedOnTallyR1CommitteeIds ++ disqualifiedOnTallyR3CommitteeIds

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
    require(!getAllDisqualifiedCommitteeIds.contains(r1Data.issuerID), "Committee member was disqualified")
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
    if (currentRound != TallyPhases.Init)
      throw new IllegalStateException("Unexpected state! Round 1 should be executed only in the Init state.")

    if (numberOfExperts <= 0 || summator.getDelegationsSum.isEmpty) {
      // there is nothing to do on Round 1 if there are no experts or no proposals
      currentRound = TallyPhases.TallyR1
      return Try(this)
    }

    val submittedCommitteeIds = r1DataAll.map(_.issuerID).toSet
    require(submittedCommitteeIds.size == r1DataAll.size, "More than one TallyR1Data from the same committee member is not allowed")
    require(submittedCommitteeIds.intersect(getAllDisqualifiedCommitteeIds).isEmpty, "Disqualified members are not allowed to submit r1Data!")

    val expectedCommitteeIds = allCommitteeIds.diff(getAllDisqualifiedCommitteeIds)
    val failedCommitteeIds = expectedCommitteeIds.diff(submittedCommitteeIds)

    val uvDelegationsSum = summator.getDelegationsSum
    val proposalIds = uvDelegationsSum.keys

    delegationsSharesSum = r1DataAll.foldLeft(Map[Int,Array[GroupElement]]()) { (acc, r1Data) =>
      proposalIds.foldLeft(acc) { (acc2, proposalId) =>
        val decryptionSharesSum = acc2.getOrElse(proposalId, Array.fill(numberOfExperts)(group.groupIdentity))
        val decryptionShare = r1Data.decryptionShares(proposalId).decryptedC1.map(_._1)
        require(decryptionSharesSum.size == decryptionShare.size)

        val newSum = decryptionSharesSum.zip(decryptionShare).map(s => s._1.multiply(s._2).get)
        acc2 + (proposalId -> newSum)
      }
    }

    disqualifiedOnTallyR1CommitteeIds = failedCommitteeIds
    currentRound = TallyPhases.TallyR1
    this
  }

  /**
    * In the case some committee members haven't submitted decryption shares on Tally Round 1, they are considered
    * failed and all other committee members should jointly reconstruct their secret keys. At Round 2, each qualified committee
    * member submits his share of a secret key of a failed committee member (for all failed CMs).
    *
    * TODO: R1Data should be taken from RoundsDataStorage
    */
  def generateR2Data(committeeMemberKey: KeyPair, dkgR1DataAll: Seq[R1Data]): Try[TallyR2Data] = Try {
    if (currentRound != TallyPhases.TallyR1)
      throw new IllegalStateException("Unexpected state! Round 2 should be executed only in the TallyR1 state.")

    val myId = cmIdentifier.getId(committeeMemberKey._2).get

    if (disqualifiedOnTallyR1CommitteeIds.nonEmpty) {
      // we need to act only if there are committee members that failed during Tally Round 1
      val recoveryShares = disqualifiedOnTallyR1CommitteeIds.toArray.map { id =>
        val recoveryShare = DistrKeyGen.generateRecoveryKeyShare(ctx, cmIdentifier,
          committeeMemberKey, cmIdentifier.getPubKey(id).get, dkgR1DataAll).get
        (id, recoveryShare)
      }
      TallyR2Data(myId, recoveryShares)
    } else {
      // there are no failed memebers, so nothing to add
      TallyR2Data(myId, Array())
    }
  }

  def verifyRound2Data(committePubKey: PubKey, r2Data: TallyR2Data, dkgR1DataAll: Seq[R1Data]): Try[Unit] = Try {
    if (currentRound != TallyPhases.TallyR1)
      throw new IllegalStateException("Unexpected state! Round 2 should be executed only in the TallyR1 state.")

    val committeID = cmIdentifier.getId(committePubKey).get
    require(r2Data.issuerID == committeID, "Committee identifier in TallyR2Data is invalid")

    require(r2Data.violatorsShares.map(_._1).toSet == disqualifiedOnTallyR1CommitteeIds, "Unexpected set of recovery shares")
    r2Data.violatorsShares.foreach { s =>
      val violatorPubKey = cmIdentifier.getPubKey(s._1).get
      require(DistrKeyGen.validateRecoveryKeyShare(ctx, cmIdentifier, committePubKey, violatorPubKey, dkgR1DataAll, s._2).isSuccess)
    }
  }

  /**
    * At the end of the Round 2, all decryption shares should be available and, thus, the delegations can be decrypted.
    * Given that delegations are available we can sum up all the experts ballot weighted by delegated voting power.
    *
    * @param r2DataAll
    * @param expertBallots
    * @return
    */
  def executeRound2(summator: BallotsSummator, r2DataAll: Seq[TallyR2Data], expertBallots: Seq[ExpertBallot]): Try[Unit] = Try {
    if (currentRound != TallyPhases.TallyR1)
      throw new IllegalStateException("Unexpected state! Round 2 should be executed only in the TallyR1 state.")

    // Step 1: restore private keys of failed committee members
    if (disqualifiedOnTallyR1CommitteeIds.nonEmpty) {
      val restoredKeys = disqualifiedOnTallyR1CommitteeIds.map{ id =>
        val pubKey = cmIdentifier.getPubKey(id).get
        val recoveryShares = r2DataAll.map(_.violatorsShares.find(_._1 == id).map(_._2)).flatten

        // note that there should be at least t/2 recovery shares, where t is the size of the committee, otherwise recovery will fail
        val privKey = DistrKeyGen.recoverPrivateKeyByOpenedShares(ctx, cmIdentifier.pubKeys.size, recoveryShares, Some(pubKey)).get
        (pubKey -> privKey)
      }

      // update state and store newly restored keys
      allDisqualifiedCommitteeKeys = allDisqualifiedCommitteeKeys ++ restoredKeys
    }

    // Step 2: calculate decryption shares of failed committee members and at the same sum them up with already accumulated shares
    delegationsSharesSum = delegationsSharesSum.map { case (proposalId, shares) =>
      val delegationsSum = summator.getDelegationsSum(proposalId)
      assert(delegationsSum.size == shares.size)
      val updatedShares = allDisqualifiedCommitteeKeys.foldLeft(shares) { (acc, keys) =>
        val decryptedC1 = delegationsSum.map(_.c1.pow(keys._2).get)
        shares.zip(decryptedC1).map(x => x._1.multiply(x._2).get)
      }
      (proposalId -> updatedShares)
    }

    // Step 3: decrypt delegations

    // Step 4: sum up expert ballots with delegations
  }

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