package io.iohk.protocol.voting.approval.uni_delegation.tally

import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.core.crypto.primitives.dlog.GroupElement
import io.iohk.protocol.Identifier
import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.keygen.{DistrKeyGen, KeyRecovery}
import io.iohk.protocol.nizk.ElgamalDecrNIZK
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.uni_delegation.UniDelegExpertBallot
import io.iohk.protocol.voting.approval.uni_delegation.tally.UniDelegTally.UniDelegStages
import io.iohk.protocol.voting.approval.uni_delegation.tally.datastructures.{UniDelegTallyR1Data, UniDelegTallyR2Data, UniDelegTallyR3Data, UniDelegTallyR4Data}
import io.iohk.protocol.voting.common.Tally
import io.iohk.protocol.voting.preferential.tally.datastructures.PrefTallyR1Data

import scala.util.Try

/**
  * UniDelegTally class implements the 4-round tally protocol for the approval voting scheme with unified delegation.
  * In this scheme a ballot includes votes for all registered proposals.
  * If voter delegates his voting power, it is delegated for all proposals to the same expert.
  *
  * @param ctx                                  ApprovalContext
  * @param cmIdentifier                         Identifier object that maps public keys of committee members to their integer identifiers
  * @param disqualifiedBeforeTallyCommitteeKeys some committee members can be disqualified during the previous stage before
  *                                             Tally begins. In this case their keys might already been
  *                                             restored (e.g., depending on what round of DKG they were disqualified). They
  *                                             are passed here because they will be needed for generating decryption shares.
  */
class UniDelegTally (ctx: ApprovalContext,
                     cmIdentifier: Identifier[Int],
                     disqualifiedBeforeTallyCommitteeKeys: Map[PubKey, Option[PrivKey]])
  extends KeyRecovery(ctx.cryptoContext, cmIdentifier) with Tally {

  import ctx.cryptoContext.{group, hash}
  type R1DATA = UniDelegTallyR1Data
  type R2DATA = UniDelegTallyR2Data
  type R3DATA = UniDelegTallyR3Data
  type R4DATA = UniDelegTallyR4Data
  type SUMMATOR = UniDelegBallotsSummator
  type EXPERTBALLOT = UniDelegExpertBallot
  type RESULT = List[Vector[BigInt]]
  type M = UniDelegTally

  private var currentRound = UniDelegStages.Init
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

  private var choicesSum = List[Vector[ElGamalCiphertext]]()        // For each proposal holds the summation of choices of voters and experts.
  private var choicesSharesSum = List[Vector[GroupElement]]()       // For each proposal holds the summation of decryption shares of committee members that are used to decrypt choicesSum.
  private var choices = List[Vector[BigInt]]()                      // For each proposal holds a voting result, e.g. number of votes
  def getChoicesSum = choicesSum
  def getChoicesSharesSum = choicesSharesSum
  def getChoices = choices

  override def getResult: Try[List[Vector[BigInt]]] = Try(getChoices)

  def generateR1Data(summator: UniDelegBallotsSummator, committeeMemberKey: KeyPair): Try[UniDelegTallyR1Data] = Try {
    val (privKey, pubKey) = committeeMemberKey
    val committeeId = cmIdentifier.getId(pubKey).get

    val decryptedC1Shares = summator.getDelegationsSum.getOrElse(Vector())map { unit =>
      val decryptedC1 = unit.c1.pow(privKey).get
      val proof = ElgamalDecrNIZK.produceNIZK(unit, privKey).get
      (decryptedC1, proof)
    }

    PrefTallyR1Data(committeeId, decryptedC1Shares)
  }

  def verifyRound1Data(summator: UniDelegBallotsSummator, committePubKey: PubKey, r1Data: UniDelegTallyR1Data): Boolean = Try {
    val delegationsSum = summator.getDelegationsSum
    val committeID = cmIdentifier.getId(committePubKey).get

    require(r1Data.issuerID == committeID, "Committee identifier in R1Data is invalid")
    require(!getAllDisqualifiedCommitteeIds.contains(r1Data.issuerID), "Committee member was disqualified")
    require(r1Data.validate(ctx.cryptoContext, committePubKey, delegationsSum.getOrElse(Vector())), "Invalid decryption share")
  }.isSuccess

  def executeRound1(summator: UniDelegBallotsSummator, r1DataAll: Seq[UniDelegTallyR1Data]): Try[UniDelegTally] = Try {
    if (currentRound != UniDelegStages.Init)
      throw new IllegalStateException("Unexpected state! Round 1 should be executed only in the Init state.")
    require(summator.getChoicesSum.isDefined, "There are no ballots")

    if (ctx.numberOfExperts > 0) {
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
    }
    currentRound = UniDelegStages.TallyR1
    choicesSum = summator.getChoicesSum.get
    this
  }

  def generateR2Data(committeeMemberKey: KeyPair, dkgR1DataAll: Seq[R1Data]): Try[UniDelegTallyR2Data] = Try {
    if (currentRound != UniDelegStages.TallyR1)
      throw new IllegalStateException("Unexpected state! Round 2 should be executed only in the TallyR1 state.")

    prepareRecoverySharesData(committeeMemberKey, disqualifiedOnTallyR1CommitteeIds, dkgR1DataAll).get
  }

  def verifyRound2Data(committePubKey: PubKey, r2Data: UniDelegTallyR2Data, dkgR1DataAll: Seq[R1Data]): Try[Unit] = Try {
    if (currentRound != UniDelegStages.TallyR1)
      throw new IllegalStateException("Unexpected state! Round 2 should be executed only in the TallyR1 state.")

    require(verifyRecoverySharesData(committePubKey, r2Data, disqualifiedOnTallyR1CommitteeIds, dkgR1DataAll).isSuccess)
  }

  /**
    * At the end of the Round 2, all decryption shares should be available and, thus, the delegations can be decrypted.
    * Given that delegations are available we can sum up all the experts ballot weighted by delegated voting power.
    */
  def executeRound2(r2DataAll: Seq[UniDelegTallyR2Data], expertBallots: Seq[UniDelegExpertBallot]): Try[UniDelegTally] = Try {
    if (currentRound != UniDelegStages.TallyR1)
      throw new IllegalStateException("Unexpected state! Round 2 should be executed only in the TallyR1 state.")
    expertBallots.foreach(b => assert(b.expertId >= 0 && b.expertId < ctx.numberOfExperts))

    // Step 1: restore private keys of failed committee members
    val restoredKeys = restorePrivateKeys(disqualifiedOnTallyR1CommitteeIds, r2DataAll).get
    val updatedAllDisqualifiedCommitteeKeys = allDisqualifiedCommitteeKeys ++ restoredKeys

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

    // Step 4: sum up choices part of ballots by adding expert ballots weighted by delegations
    choicesSum = expertBallots.foldLeft(choicesSum) { (acc, ballot) =>
      assert(acc.size == ballot.choices.size)
      val delegatedStake = delegationsDecrypted.get(ballot.expertId)
      acc.zip(ballot.choices).map { case (v1, v2) =>
        assert(v1.size == v2.size)
        v1.zip(v2).map { case (b1, b2) =>
          val weightedVote = b2.pow(delegatedStake).get
          b1.multiply(weightedVote).get
        }
      }
    }

    // if we reached this point execution was successful, so update state variables
    allDisqualifiedCommitteeKeys = updatedAllDisqualifiedCommitteeKeys
    delegationsSharesSum = updatedDelegationsSharesSum
    delegations = delegationsDecrypted
    currentRound = UniDelegStages.TallyR2
    this
  }

  def generateR3Data(committeeMemberKey: KeyPair): Try[UniDelegTallyR3Data] = Try {
    if (currentRound != UniDelegStages.TallyR2)
      throw new IllegalStateException("Unexpected state! Round 3 should be executed only in the TallyR2 state.")

    val (privKey, pubKey) = committeeMemberKey
    val decryptionShares = choicesSum.map { v =>
      v.map { b =>
        val decryptedC1 = b.c1.pow(privKey).get
        val proof = ElgamalDecrNIZK.produceNIZK(b, privKey).get
        (decryptedC1, proof)
      }
    }

    val committeeId = cmIdentifier.getId(pubKey).get
    UniDelegTallyR3Data(committeeId, decryptionShares)
  }

  def verifyRound3Data(committePubKey: PubKey, r3Data: UniDelegTallyR3Data): Try[Unit] = Try {
    val committeID = cmIdentifier.getId(committePubKey).get

    require(r3Data.issuerID == committeID, "Committee identifier in R3Data is invalid")
    require(!getAllDisqualifiedCommitteeIds.contains(r3Data.issuerID), "Committee member was disqualified")
    require(r3Data.choicesDecryptedC1.length == ctx.numberOfProposals, "Not all proposals are decrypted")
    r3Data.choicesDecryptedC1.foreach(v => require(v.length == ctx.numberOfChoices))
    require(r3Data.validate(ctx.cryptoContext, committePubKey, choicesSum), "Invalid decryption shares")
  }

  def executeRound3(r3DataAll: Seq[UniDelegTallyR3Data]): Try[UniDelegTally] = Try {
    if (currentRound != UniDelegStages.TallyR2)
      throw new IllegalStateException("Unexpected state! Round 3 should be executed only in the TallyR2 state.")

    if (choicesSum.isEmpty) {
      // there is nothing to do on Round 3 if there is nothing to decrypt
      currentRound = UniDelegStages.TallyR3
      return Try(this)
    }

    val submittedCommitteeIds = r3DataAll.map(_.issuerID).toSet
    require(submittedCommitteeIds.size == r3DataAll.size, "More than one TallyR1Data from the same committee member is not allowed")
    require(submittedCommitteeIds.intersect(getAllDisqualifiedCommitteeIds).isEmpty, "Disqualified members are not allowed to submit r1Data!")

    val expectedCommitteeIds = allCommitteeIds.diff(getAllDisqualifiedCommitteeIds)
    val failedCommitteeIds = expectedCommitteeIds.diff(submittedCommitteeIds)

    val init = List.fill(ctx.numberOfProposals)(Vector.fill(ctx.numberOfChoices)(group.groupIdentity))

    choicesSharesSum = r3DataAll.foldLeft(init) { (acc, r3Data) =>
      assert(acc.length == r3Data.choicesDecryptedC1.length)
      acc.zip(r3Data.choicesDecryptedC1).map { case (v1, v2) =>
        assert(v1.length == v2.length)
        v1.zip(v2).map(x => x._1.multiply(x._2._1).get)
      }
    }

    disqualifiedOnTallyR3CommitteeIds = failedCommitteeIds
    currentRound = UniDelegStages.TallyR3

    this
  }

  def generateR4Data(committeeMemberKey: KeyPair, dkgR1DataAll: Seq[R1Data]): Try[UniDelegTallyR4Data] = Try {
    if (currentRound != UniDelegStages.TallyR3)
      throw new IllegalStateException("Unexpected state! Round 4 should be executed only in the TallyR3 state.")

    prepareRecoverySharesData(committeeMemberKey, disqualifiedOnTallyR3CommitteeIds, dkgR1DataAll).get
  }

  def verifyRound4Data(committePubKey: PubKey, r4Data: UniDelegTallyR4Data, dkgR1DataAll: Seq[R1Data]): Try[Unit] = Try {
    if (currentRound != UniDelegStages.TallyR3)
      throw new IllegalStateException("Unexpected state! Round 4 should be executed only in the TallyR3 state.")

    require(verifyRecoverySharesData(committePubKey, r4Data, disqualifiedOnTallyR3CommitteeIds, dkgR1DataAll).isSuccess)
  }

  def executeRound4(r4DataAll: Seq[UniDelegTallyR4Data]): Try[UniDelegTally] = Try {
    if (currentRound != UniDelegStages.TallyR3)
      throw new IllegalStateException("Unexpected state! Round 4 should be executed only in the TallyR3 state.")

    // Step 1: restore private keys of failed committee members
    val restoredKeys = restorePrivateKeys(disqualifiedOnTallyR3CommitteeIds, r4DataAll).get
    val updatedAllDisqualifiedCommitteeKeys = allDisqualifiedCommitteeKeys ++ restoredKeys

    // Step 2: calculate decryption shares of disqualified committee members and at the same sum them up with already accumulated shares
    val updatedChoicesSharesSum = choicesSharesSum.zipWithIndex.map { case (shares, i) =>
      updatedAllDisqualifiedCommitteeKeys.foldLeft(shares) { (acc, keys) =>
        val decryptedC1 = choicesSum(i).map(_.c1.pow(keys._2).get)
        acc.zip(decryptedC1).map(x => x._1.multiply(x._2).get)
      }
    }

    // Step 3: decrypt final result for each proposal
    choices = choicesSum.zip(updatedChoicesSharesSum).map { case (v, shares) =>
      assert(v.size == shares.size)
      v.zip(shares).map { case (encr, decr) =>
        LiftedElGamalEnc.discreteLog(encr.c2.divide(decr).get).get
      }
    }

    // if we reached this point execution was successful, so update state variables
    allDisqualifiedCommitteeKeys = updatedAllDisqualifiedCommitteeKeys
    choicesSharesSum = updatedChoicesSharesSum
    currentRound = UniDelegStages.TallyR4
    this
  }
}

object UniDelegTally {
  object UniDelegStages extends Enumeration {
    val Init, TallyR1, TallyR2, TallyR3, TallyR4 = Value
  }
}