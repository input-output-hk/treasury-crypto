package io.iohk.protocol.voting.preferential.tally

import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.core.crypto.primitives.dlog.GroupElement
import io.iohk.protocol.Identifier
import io.iohk.protocol.keygen.DistrKeyGen
import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.nizk.ElgamalDecrNIZK
import io.iohk.protocol.tally.TallyCommon
import io.iohk.protocol.tally.datastructures.TallyR2Data
import io.iohk.protocol.voting.preferential.{PreferentialContext, PreferentialExpertBallot}
import io.iohk.protocol.voting.preferential.tally.PreferentialTally.PrefStages
import io.iohk.protocol.voting.preferential.tally.datastructures.PrefTallyR1Data

import scala.util.Try

class PreferentialTally(ctx: PreferentialContext,
                        cmIdentifier: Identifier[Int],
                        disqualifiedBeforeTallyCommitteeKeys: Map[PubKey, Option[PrivKey]]) extends TallyCommon(ctx.cryptoContext, cmIdentifier) {
  import ctx.cryptoContext.{group, hash}

  private var currentRound = PrefStages.Init
  def getCurrentRound = currentRound

  private val allCommitteeIds = cmIdentifier.pubKeys.map(cmIdentifier.getId(_).get).toSet
  private val disqualifiedBeforeTallyCommitteeIds = disqualifiedBeforeTallyCommitteeKeys.keySet.map(cmIdentifier.getId(_).get)
  private var disqualifiedOnTallyR1CommitteeIds = Set[Int]()
  private var disqualifiedOnTallyR3CommitteeIds = Set[Int]()
  def getDisqualifiedOnTallyCommitteeIds = disqualifiedOnTallyR1CommitteeIds ++ disqualifiedOnTallyR3CommitteeIds
  def getAllDisqualifiedCommitteeIds = disqualifiedBeforeTallyCommitteeIds ++ getDisqualifiedOnTallyCommitteeIds

  // here we will collect restored secret keys of committee members, for now initialize it with the restored keys provided in the constructor
  private var allDisqualifiedCommitteeKeys = disqualifiedBeforeTallyCommitteeKeys.filter(_._2.isDefined).mapValues(_.get)

  private var delegationsSum: Option[Vector[ElGamalCiphertext]] = None
  private var delegationsSharesSum: Option[Vector[GroupElement]] = None
  private var delegations: Option[Vector[BigInt]] = None
  def getDelegationsSharesSum = delegationsSharesSum
  def getDelegations = delegations

  private var rankingsSum = List[Vector[ElGamalCiphertext]]()        // For each proposal holds the summation of rankings of voters and experts.
  private var rankingsSharesSum = List[Vector[GroupElement]]()       // For each proposal holds the summation of decryption shares of committee members that are used to decrypt rankingsSum.
  private var scores = Map[Int, Vector[BigInt]]()                   // For each proposal holds a voting result, e.g. number of votes
  def getRankingsSum = rankingsSum
  def getRankingsSharesSum = rankingsSharesSum
  def getScores = scores

  def generateR1Data(summator: PreferentialBallotsSummator, committeeMemberKey: KeyPair): Try[PrefTallyR1Data] = Try {
    val (privKey, pubKey) = committeeMemberKey
    val committeeId = cmIdentifier.getId(pubKey).get

    val decryptedC1Shares = summator.getDelegationsSum.getOrElse(Vector())map { unit =>
      val decryptedC1 = unit.c1.pow(privKey).get
      val proof = ElgamalDecrNIZK.produceNIZK(unit, privKey).get
      (decryptedC1, proof)
    }

    PrefTallyR1Data(committeeId, decryptedC1Shares)
  }

  def verifyRound1Data(summator: PreferentialBallotsSummator, committePubKey: PubKey, r1Data: PrefTallyR1Data): Boolean = Try {
    val delegationsSum = summator.getDelegationsSum
    val committeID = cmIdentifier.getId(committePubKey).get

    require(r1Data.issuerID == committeID, "Committee identifier in R1Data is invalid")
    require(!getAllDisqualifiedCommitteeIds.contains(r1Data.issuerID), "Committee member was disqualified")
    require(r1Data.validate(ctx.cryptoContext, committePubKey, delegationsSum.getOrElse(Vector())), "Invalid decryption share")
  }.isSuccess

  def executeRound1(summator: PreferentialBallotsSummator, r1DataAll: Seq[PrefTallyR1Data]): Try[PreferentialTally] = Try {
    if (currentRound != PrefStages.Init)
      throw new IllegalStateException("Unexpected state! Round 1 should be executed only in the Init state.")

    if (ctx.numberOfExperts <= 0) {
      // there is nothing to do on Round 1 if there are no experts or no proposals
      currentRound = PrefStages.TallyR1
      return Try(this)
    }

    require(summator.getRankingsSum.isDefined, "There are no ballots")

    val submittedCommitteeIds = r1DataAll.map(_.issuerID).toSet
    require(submittedCommitteeIds.size == r1DataAll.size, "More than one TallyR1Data from the same committee member is not allowed")
    require(submittedCommitteeIds.intersect(getAllDisqualifiedCommitteeIds).isEmpty, "Disqualified members are not allowed to submit r1Data!")

    val expectedCommitteeIds = allCommitteeIds.diff(getAllDisqualifiedCommitteeIds)
    val failedCommitteeIds = expectedCommitteeIds.diff(submittedCommitteeIds)

    delegationsSharesSum = Some(r1DataAll.foldLeft(Vector.fill(ctx.numberOfExperts)(group.groupIdentity)) { (acc, data) =>
      val decryptionShares = data.delegDecryptedC1.map(_._1)
      require(decryptionShares.size == acc.size)
      decryptionShares.zip(acc).map(s => s._1.multiply(s._2).get).toVector
    })

    disqualifiedOnTallyR1CommitteeIds = failedCommitteeIds
    delegationsSum = summator.getDelegationsSum
    currentRound = PrefStages.TallyR1
    rankingsSum = summator.getRankingsSum.get
    this
  }

  def generateR2Data(committeeMemberKey: KeyPair, dkgR1DataAll: Seq[R1Data]): Try[TallyR2Data] = Try {
    if (currentRound != PrefStages.TallyR1)
      throw new IllegalStateException("Unexpected state! Round 2 should be executed only in the TallyR1 state.")

    prepareRecoverySharesData(committeeMemberKey, disqualifiedOnTallyR1CommitteeIds, dkgR1DataAll).get
  }

  def verifyRound2Data(committePubKey: PubKey, r2Data: TallyR2Data, dkgR1DataAll: Seq[R1Data]): Try[Unit] = Try {
    if (currentRound != PrefStages.TallyR1)
      throw new IllegalStateException("Unexpected state! Round 2 should be executed only in the TallyR1 state.")

    val committeID = cmIdentifier.getId(committePubKey).get
    require(r2Data.issuerID == committeID, "Committee identifier in TallyR2Data is invalid")

    require(r2Data.violatorsShares.map(_._1).toSet == disqualifiedOnTallyR1CommitteeIds, "Unexpected set of recovery shares")
    r2Data.violatorsShares.foreach { s =>
      val violatorPubKey = cmIdentifier.getPubKey(s._1).get
      require(DistrKeyGen.validateRecoveryKeyShare(ctx.cryptoContext, cmIdentifier, committePubKey, violatorPubKey, dkgR1DataAll, s._2).isSuccess)
    }
  }

  /**
    * At the end of the Round 2, all decryption shares should be available and, thus, the delegations can be decrypted.
    * Given that delegations are available we can sum up all the experts ballot weighted by delegated voting power.
    */
  def executeRound2(r2DataAll: Seq[TallyR2Data], expertBallots: Seq[PreferentialExpertBallot]): Try[PreferentialTally] = Try {
    if (currentRound != PrefStages.TallyR1)
      throw new IllegalStateException("Unexpected state! Round 2 should be executed only in the TallyR1 state.")
    expertBallots.foreach(b => assert(b.expertId >= 0 && b.expertId < ctx.numberOfExperts))

    // Step 1: restore private keys of failed committee members
    val updatedAllDisqualifiedCommitteeKeys = if (disqualifiedOnTallyR1CommitteeIds.nonEmpty) {
      val restoredKeys = disqualifiedOnTallyR1CommitteeIds.map{ id =>
        val pubKey = cmIdentifier.getPubKey(id).get
        val recoveryShares = r2DataAll.map(_.violatorsShares.find(_._1 == id).map(_._2)).flatten

        // note that there should be at least t/2 recovery shares, where t is the size of the committee, otherwise recovery will fail
        val privKey = DistrKeyGen.recoverPrivateKeyByOpenedShares(ctx.cryptoContext, cmIdentifier.pubKeys.size, recoveryShares, Some(pubKey)).get
        (pubKey -> privKey)
      }
      // update state and store newly restored keys
      allDisqualifiedCommitteeKeys ++ restoredKeys
    } else allDisqualifiedCommitteeKeys

    // Step 2: calculate decryption shares of failed committee members and at the same sum them up with already accumulated shares
    val updatedDelegationsSharesSum = delegationsSharesSum.map { x =>
      updatedAllDisqualifiedCommitteeKeys.foldLeft(x) { (acc, keys) =>
        val decryptedC1 = delegationsSum.get.map(_.c1.pow(keys._2).get)
        acc.zip(decryptedC1).map(x => x._1.multiply(x._2).get)
      }
    }

    // Step 3: decrypt delegations, which signifies how much stake was delegated to each expert
    val delegationsDecrypted = delegationsSum.map { x =>
      x.zip(updatedDelegationsSharesSum.get).map { case (encr, decr) =>
        LiftedElGamalEnc.discreteLog(encr.c2.divide(decr).get).get
      }
    }

    // Step 4: sum up rankings part of ballots by adding expert ballots weighted by delegations
    rankingsSum = expertBallots.foldLeft(rankingsSum) { (acc, ballot) =>
      assert(acc.size == ballot.rankVectors.size)
      val delegatedStake = delegationsDecrypted.get(ballot.expertId)
      acc.zip(ballot.rankVectors).map { case (v1, v2) =>
        assert(v1.size == v2.rank.size)
        v1.zip(v2.rank).map { case (b1, b2) =>
          val weightedVote = b2.pow(delegatedStake).get
          b1.multiply(weightedVote).get
        }
      }
    }

    // if we reached this point execution was successful, so update state variables
    allDisqualifiedCommitteeKeys = updatedAllDisqualifiedCommitteeKeys
    delegationsSharesSum = updatedDelegationsSharesSum
    delegations = delegationsDecrypted
    currentRound = PrefStages.TallyR2
    this
  }
}

object PreferentialTally {
  object PrefStages extends Enumeration {
    val Init, TallyR1, TallyR2, TallyR3, TallyR4 = Value
  }
}