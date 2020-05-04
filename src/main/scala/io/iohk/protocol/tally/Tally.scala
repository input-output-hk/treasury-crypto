package io.iohk.protocol.tally

import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.core.crypto.primitives.hash.CryptographicHash
import io.iohk.protocol.keygen.DistrKeyGen
import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.nizk.ElgamalDecrNIZK
import io.iohk.protocol.storage.RoundsDataStorage
import io.iohk.protocol.tally.Tally.{Result, Stages}
import io.iohk.protocol.tally.datastructures._
import io.iohk.protocol.voting.VotingOptions
import io.iohk.protocol.voting.ballots.ExpertBallot
import io.iohk.protocol.{CryptoContext, Identifier}

import scala.util.Try

/**
  * Tally class encapsulates the 4-round tally protocol.
  * Recall that during the first round committee members submit decryption shares needed to decrypt the amount of
  * delegated stake to each expert for each proposal.
  * During the second round committee members submit recovery shares needed to restore secret keys of those members
  * who failed to submit valid decryption shares in the first round, so that given restored keys everyone can
  * reconstruct missing decryption shares.
  * On the third round committee members submit decryption shares needed to decrypt the voting result for each proposal.
  * On the fourth round committee members submit recovery shares needed to restore secret keys of those members who failed to submit
  * valid decryption shares in the third round, so that given restored keys everyone can reconstruct missing decryption shares.
  *
  * See details of the protocol on Fig. 11 in the spec: treasury-crypto/docs/voting_protocol_spec/Treasury_voting_protocol_spec.pdf
  *
  * The Tally class is supposed to be used both by committee members, who participate in the protocol, and regular observers,
  * who are able to verify each message and calculate the tally result for each proposal.
  *
  * The interface is the following, each round is represented by 3 functions (X is a round number):
  *   - generateRXData    - is used by a committee member to generate a round-specific data;
  *   - verifyRXData      - is used by everyone who follows the tally protocol to verify a round-specific data produced
  *                         by a committee member (e.g., in a blockchain setting, if a round-specific data is submitted as
  *                         a transaction, verifyRXData will be used by every node to verify such transaction);
  *   - executeRoundX     - is used by everyone to update the state according to the provided set of round-specific data
  *                         from committee members. Note that it is responsibility of the caller to verify the data provided
  *                         to the "executeRoundX";
  * Note that Tally is a stateful class. Each successful call to the "executeRoundX" function updates internal variables. On the
  * other hand, calls to "generateRXData" and "verifyRXData" don't produce any side-effects.
  * Also note that "executeRoundX" should be called sequentially one after another, otherwise they will return error.
  *
  * @param ctx                                  CryptoContext
  * @param cmIdentifier                         Identifier object that maps public keys of committee members to their integer identifiers
  * @param numberOfExperts                      number of registered experts in the system (recall that the number of
  *                                             experts defines the size of voter's unit vectors)
  * @param disqualifiedBeforeTallyCommitteeKeys some committee members can be disqualified during the DKG stage before
  *                                             Tally begins. In this case their keys might already been
  *                                             restored (depending on what round of DKG they were disqualified). They
  *                                             are passed here because they will be needed for generating decryption shares.
  */
class Tally(ctx: CryptoContext,
            cmIdentifier: Identifier[Int],
            numberOfExperts: Int,
            disqualifiedBeforeTallyCommitteeKeys: Map[PubKey, Option[PrivKey]]) {
  import ctx.{group, hash}

  private var currentRound = Stages.Init
  def getCurrentRound = currentRound

  private val allCommitteeIds = cmIdentifier.pubKeys.map(cmIdentifier.getId(_).get).toSet
  private val disqualifiedBeforeTallyCommitteeIds = disqualifiedBeforeTallyCommitteeKeys.keySet.map(cmIdentifier.getId(_).get)
  private var disqualifiedOnTallyR1CommitteeIds = Set[Int]()
  private var disqualifiedOnTallyR3CommitteeIds = Set[Int]()
  def getDisqualifiedOnTallyCommitteeIds = disqualifiedOnTallyR1CommitteeIds ++ disqualifiedOnTallyR3CommitteeIds
  def getAllDisqualifiedCommitteeIds = disqualifiedBeforeTallyCommitteeIds ++ getDisqualifiedOnTallyCommitteeIds

  // here we will collect restored secret keys of committee members, for now initialize it with the restored keys provided in the constructor
  private var allDisqualifiedCommitteeKeys = disqualifiedBeforeTallyCommitteeKeys.filter(_._2.isDefined).mapValues(_.get)

  private var delegationsSum = Map[Int, Vector[ElGamalCiphertext]]()    // For each proposal holds the summation of delegation parts of voter's encrypted unit vectors.
  private var delegationsSharesSum = Map[Int, Vector[GroupElement]]()   // For each proposal holds the summation of decryption shares of committee members. Will be used to decrypt delegationsSum.
  private var delegations = Map[Int, Vector[BigInt]]()                  // For each proposal holds a vector of decrypted delegations. Each element of the vector is an amount of delegated stake.
  def getDelegationsSharesSum = delegationsSharesSum
  def getDelegations = delegations

  private var choicesSum = Map[Int, Vector[ElGamalCiphertext]]()        // For each proposal holds the summation of choices parts of encrypted unit vectors of voters and experts.
  private var choicesSharesSum = Map[Int, Vector[GroupElement]]()       // For each proposal holds the summation of decryption shares of committee members that are used to decrypt choicesSum.
  private var choices = Map[Int, Result]()                              // For each proposal holds a voting result, i.e. number of Yes, No and Abstain votes.
  def getChoicesSum = choicesSum
  def getChoicesSharesSum = choicesSharesSum
  def getChoices = choices


  def generateR1Data(summator: BallotsSummator, committeeMemberKey: KeyPair): Try[TallyR1Data] = Try {
    val (privKey, pubKey) = committeeMemberKey
    val decryptionShares = Tally.generateDecryptionShares(summator.getDelegationsSum, privKey)
    val committeeId = cmIdentifier.getId(pubKey).get
    TallyR1Data(committeeId, decryptionShares)
  }

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

  def executeRound1(summator: BallotsSummator, r1DataAll: Seq[TallyR1Data]): Try[Tally] = Try {
    if (currentRound != Stages.Init)
      throw new IllegalStateException("Unexpected state! Round 1 should be executed only in the Init state.")

    if (numberOfExperts <= 0 || summator.getDelegationsSum.isEmpty) {
      // there is nothing to do on Round 1 if there are no experts or no proposals
      currentRound = Stages.TallyR1
      return Try(this)
    }

    val submittedCommitteeIds = r1DataAll.map(_.issuerID).toSet
    require(submittedCommitteeIds.size == r1DataAll.size, "More than one TallyR1Data from the same committee member is not allowed")
    require(submittedCommitteeIds.intersect(getAllDisqualifiedCommitteeIds).isEmpty, "Disqualified members are not allowed to submit r1Data!")

    val expectedCommitteeIds = allCommitteeIds.diff(getAllDisqualifiedCommitteeIds)
    val failedCommitteeIds = expectedCommitteeIds.diff(submittedCommitteeIds)

    val proposalIds = summator.getDelegationsSum.keys.toSeq

    delegationsSharesSum = Tally.sumUpDecryptionShares(r1DataAll, numberOfExperts, proposalIds)

    disqualifiedOnTallyR1CommitteeIds = failedCommitteeIds
    delegationsSum = summator.getDelegationsSum
    choicesSum = summator.getChoicesSum
    currentRound = Stages.TallyR1
    this
  }

  /**
    * The DKG Round 1 data is needed in case we need to restore private keys of disqualified committee members
    * It should be provided by DistrKeyGen object
    */
  def generateR2Data(committeeMemberKey: KeyPair, dkgR1DataAll: Seq[R1Data]): Try[TallyR2Data] = Try {
    if (currentRound != Stages.TallyR1)
      throw new IllegalStateException("Unexpected state! Round 2 should be executed only in the TallyR1 state.")

    prepareRecoverySharesData(committeeMemberKey, disqualifiedOnTallyR1CommitteeIds, dkgR1DataAll).get
  }

  def verifyRound2Data(committePubKey: PubKey, r2Data: TallyR2Data, dkgR1DataAll: Seq[R1Data]): Try[Unit] = Try {
    if (currentRound != Stages.TallyR1)
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
    */
  def executeRound2(r2DataAll: Seq[TallyR2Data], expertBallots: Seq[ExpertBallot]): Try[Tally] = Try {
    if (currentRound != Stages.TallyR1)
      throw new IllegalStateException("Unexpected state! Round 2 should be executed only in the TallyR1 state.")
    expertBallots.foreach(b => assert(b.expertId >= 0 && b.expertId < numberOfExperts))

    // Step 1: restore private keys of failed committee members
    val updatedAllDisqualifiedCommitteeKeys = if (disqualifiedOnTallyR1CommitteeIds.nonEmpty) {
      val restoredKeys = disqualifiedOnTallyR1CommitteeIds.map{ id =>
        val pubKey = cmIdentifier.getPubKey(id).get
        val recoveryShares = r2DataAll.map(_.violatorsShares.find(_._1 == id).map(_._2)).flatten

        // note that there should be at least t/2 recovery shares, where t is the size of the committee, otherwise recovery will fail
        val privKey = DistrKeyGen.recoverPrivateKeyByOpenedShares(ctx, cmIdentifier.pubKeys.size, recoveryShares, Some(pubKey)).get
        (pubKey -> privKey)
      }
      // update state and store newly restored keys
      allDisqualifiedCommitteeKeys ++ restoredKeys
    } else allDisqualifiedCommitteeKeys

    // Step 2: calculate decryption shares of failed committee members and at the same sum them up with already accumulated shares
    val updatedDelegationsSharesSum = delegationsSharesSum.map { case (proposalId, shares) =>
      val delegationsSumVector = delegationsSum(proposalId)
      assert(delegationsSumVector.size == shares.size)
      val updatedShares = updatedAllDisqualifiedCommitteeKeys.foldLeft(shares) { (acc, keys) =>
        val decryptedC1 = delegationsSumVector.map(_.c1.pow(keys._2).get)
        acc.zip(decryptedC1).map(x => x._1.multiply(x._2).get)
      }
      (proposalId -> updatedShares)
    }

    // Step 3: decrypt delegations. For each proposal we will have a vector of integers, which signifies how much stake
    // was delegated to each expert
    val delegationsDecrypted = delegationsSum.map { case (proposalId, encryptedDelegations) =>
      val decryptionSharesSum = updatedDelegationsSharesSum.get(proposalId).get
      assert(decryptionSharesSum.size == encryptedDelegations.size)
      val deleg = encryptedDelegations.zip(decryptionSharesSum).map { case (encr,decr) =>
        LiftedElGamalEnc.discreteLog(encr.c2.divide(decr).get).get
      }
      (proposalId -> deleg)
    }

    // Step 4: sum up choices part of the encrypted unit vectors by adding expert ballots weighted by delegations
    val init = choicesSum.mapValues(_.toArray) // we already have summed up voters choices
    choicesSum = expertBallots.foldLeft(init) { (acc, ballot) =>
      val proposalId = ballot.proposalId
      val updatedChoices = acc.getOrElse(proposalId,
        Array.fill(VotingOptions.values.size)(ElGamalCiphertext(group.groupIdentity, group.groupIdentity)))
      val delegatedStake = delegationsDecrypted.get(proposalId).map(v => v(ballot.expertId)).getOrElse(BigInt(0))

      for (i <- 0 until updatedChoices.size) {
        val weightedVote = ballot.uChoiceVector(i).pow(delegatedStake).get
        updatedChoices(i) = updatedChoices(i).multiply(weightedVote).get
      }
      acc + (proposalId -> updatedChoices)
    }.mapValues(_.toVector)

    // if we reached this point execution was successful, so update state variables
    allDisqualifiedCommitteeKeys = updatedAllDisqualifiedCommitteeKeys
    delegationsSharesSum = updatedDelegationsSharesSum
    delegations = delegationsDecrypted
    currentRound = Stages.TallyR2
    this
  }

  def generateR3Data(committeeMemberKey: KeyPair): Try[TallyR3Data] = Try {
    if (currentRound != Stages.TallyR2)
      throw new IllegalStateException("Unexpected state! Round 3 should be executed only in the TallyR2 state.")

    val (privKey, pubKey) = committeeMemberKey
    val decryptionShares = Tally.generateDecryptionShares(choicesSum, privKey)
    val committeeId = cmIdentifier.getId(pubKey).get
    TallyR1Data(committeeId, decryptionShares)
  }

  def verifyRound3Data(committePubKey: PubKey, r3Data: TallyR3Data): Try[Unit] = Try {
    val proposalIds = choicesSum.keySet
    val committeID = cmIdentifier.getId(committePubKey).get

    require(r3Data.issuerID == committeID, "Committee identifier in R1Data is invalid")
    require(!getAllDisqualifiedCommitteeIds.contains(r3Data.issuerID), "Committee member was disqualified")
    require(r3Data.decryptionShares.keySet.equals(proposalIds), "Not all decryption shares are provided")

    r3Data.decryptionShares.foreach { case (proposalId, s) =>
      require(proposalId == s.proposalId)
      require(s.validate(ctx, committePubKey, choicesSum(proposalId)).isSuccess, "Invalid decryption share")
    }
  }

  def executeRound3(r3DataAll: Seq[TallyR3Data]): Try[Tally] = Try {
    if (currentRound != Stages.TallyR2)
      throw new IllegalStateException("Unexpected state! Round 3 should be executed only in the TallyR2 state.")

    if (choicesSum.isEmpty) {
      // there is nothing to do on Round 3 if there is nothing to decrypt
      currentRound = Stages.TallyR3
      return Try(this)
    }

    val submittedCommitteeIds = r3DataAll.map(_.issuerID).toSet
    require(submittedCommitteeIds.size == r3DataAll.size, "More than one TallyR1Data from the same committee member is not allowed")
    require(submittedCommitteeIds.intersect(getAllDisqualifiedCommitteeIds).isEmpty, "Disqualified members are not allowed to submit r1Data!")

    val expectedCommitteeIds = allCommitteeIds.diff(getAllDisqualifiedCommitteeIds)
    val failedCommitteeIds = expectedCommitteeIds.diff(submittedCommitteeIds)

    val proposalIds = choicesSum.keys.toSeq

    choicesSharesSum = Tally.sumUpDecryptionShares(r3DataAll, VotingOptions.values.size, proposalIds)

    disqualifiedOnTallyR3CommitteeIds = failedCommitteeIds
    currentRound = Stages.TallyR3

    this
  }

  def generateR4Data(committeeMemberKey: KeyPair, dkgR1DataAll: Seq[R1Data]): Try[TallyR4Data] = Try {
    if (currentRound != Stages.TallyR3)
      throw new IllegalStateException("Unexpected state! Round 2 should be executed only in the TallyR1 state.")

    prepareRecoverySharesData(committeeMemberKey, disqualifiedOnTallyR3CommitteeIds, dkgR1DataAll).get
  }

  def verifyRound4Data(committePubKey: PubKey, r4Data: TallyR4Data, dkgR1DataAll: Seq[R1Data]): Try[Unit] = Try {
    if (currentRound != Stages.TallyR3)
      throw new IllegalStateException("Unexpected state! Round 4 should be executed only in the TallyR3 state.")

    require(verifyRecoverySharesData(committePubKey, r4Data, disqualifiedOnTallyR3CommitteeIds, dkgR1DataAll).isSuccess)
  }

  def executeRound4(r4DataAll: Seq[TallyR4Data]): Try[Tally] = Try {
    if (currentRound != Stages.TallyR3)
      throw new IllegalStateException("Unexpected state! Round 2 should be executed only in the TallyR1 state.")

    // Step 1: restore private keys of failed committee members
    val restoredKeys = restorePrivateKeys(disqualifiedOnTallyR3CommitteeIds, r4DataAll).get
    val updatedAllDisqualifiedCommitteeKeys = allDisqualifiedCommitteeKeys ++ restoredKeys

    // Step 2: calculate decryption shares of disqualified committee members and at the same sum them up with already accumulated shares
    val updatedChoicesSharesSum = choicesSharesSum.map { case (proposalId, shares) =>
      val choices = choicesSum(proposalId)
      assert(choices.size == shares.size)
      val updatedShares = updatedAllDisqualifiedCommitteeKeys.foldLeft(shares) { (acc, keys) =>
        val decryptedC1 = choices.map(_.c1.pow(keys._2).get)
        acc.zip(decryptedC1).map(x => x._1.multiply(x._2).get)
      }
      (proposalId -> updatedShares)
    }

    // Step 3: decrypt final result for each proposal
    choices = choicesSum.map { case (proposalId, encryptedChoices) =>
      val decryptionSharesSum = updatedChoicesSharesSum.get(proposalId).get
      assert(decryptionSharesSum.size == encryptedChoices.size)
      val choices = encryptedChoices.zip(decryptionSharesSum).map { case (encr,decr) =>
        LiftedElGamalEnc.discreteLog(encr.c2.divide(decr).get).get
      }
      (proposalId -> Result(choices(0), choices(1), choices(2)))
    }

    // if we reached this point execution was successful, so update state variables
    allDisqualifiedCommitteeKeys = updatedAllDisqualifiedCommitteeKeys
    choicesSharesSum = updatedChoicesSharesSum
    currentRound = Stages.TallyR4
    this
  }

  private def restorePrivateKeys(disqualifiedCommitteeIds: Set[Int],
                                 r4DataAll: Seq[TallyR4Data]): Try[Map[PubKey, PrivKey]] = Try {
    val restoredKeys = disqualifiedCommitteeIds.map{ id =>
      val pubKey = cmIdentifier.getPubKey(id).get
      val recoveryShares = r4DataAll.map(_.violatorsShares.find(_._1 == id).map(_._2)).flatten

      // note that there should be at least t/2 recovery shares, where t is the size of the committee, otherwise recovery will fail
      val privKey = DistrKeyGen.recoverPrivateKeyByOpenedShares(ctx, cmIdentifier.pubKeys.size, recoveryShares, Some(pubKey)).get
      (pubKey -> privKey)
    }.toMap

    restoredKeys
  }

  private def prepareRecoverySharesData(committeeMemberKey: KeyPair,
                                        disqualifiedCommitteeIds: Set[Int],
                                        dkgR1DataAll: Seq[R1Data]): Try[TallyR2Data] = Try {

    val myId = cmIdentifier.getId(committeeMemberKey._2).get
    if (disqualifiedCommitteeIds.nonEmpty) {
      // we need to act only if there are committee members that failed during Tally Round 1
      val recoveryShares = disqualifiedCommitteeIds.toSeq.map { id =>
        val recoveryShare = DistrKeyGen.generateRecoveryKeyShare(ctx, cmIdentifier,
          committeeMemberKey, cmIdentifier.getPubKey(id).get, dkgR1DataAll).get
        (id, recoveryShare)
      }
      TallyR2Data(myId, recoveryShares)
    } else {
      // there are no failed memebers, so nothing to add
      TallyR2Data(myId, Seq())
    }
  }

  private def verifyRecoverySharesData(committePubKey: PubKey,
                                       r2Data: TallyR2Data,
                                       disqualifiedCommitteeIds: Set[Int],
                                       dkgR1DataAll: Seq[R1Data]): Try[Unit] = Try {
    val committeID = cmIdentifier.getId (committePubKey).get
    require (r2Data.issuerID == committeID, "Committee identifier in TallyR2Data is invalid")
    require (r2Data.violatorsShares.map (_._1).toSet == disqualifiedCommitteeIds, "Unexpected set of recovery shares")

    r2Data.violatorsShares.foreach { s =>
      val violatorPubKey = cmIdentifier.getPubKey (s._1).get
      require (DistrKeyGen.validateRecoveryKeyShare (ctx, cmIdentifier, committePubKey, violatorPubKey, dkgR1DataAll, s._2).isSuccess)
    }
  }
}

object Tally {
  type Delegations = Seq[BigInt] // a sequence with the number of delegated coins to each expert

  object Stages extends Enumeration {
    val Init, TallyR1, TallyR2, TallyR3, TallyR4 = Value
  }

  case class Result(yes: BigInt, no: BigInt, abstain: BigInt)

  def recoverState(ctx: CryptoContext,
                   cmIdentifier: Identifier[Int],
                   numberOfExperts: Int,
                   disqualifiedBeforeTallyCommitteeKeys: Map[PubKey, Option[PrivKey]],
                   stage: Stages.Value,
                   storage: RoundsDataStorage,
                   summator: BallotsSummator): Try[Tally] = Try {

    val tally = new Tally(ctx, cmIdentifier, numberOfExperts, disqualifiedBeforeTallyCommitteeKeys)
    if (stage > Stages.Init) {
      tally.executeRound1(summator, storage.getTallyR1).get
      if (stage > Stages.TallyR1) {
        tally.executeRound2(storage.getTallyR2, storage.getExpertBallots).get
        if (stage > Stages.TallyR2) {
          tally.executeRound3(storage.getTallyR3).get
          if (stage > Stages.TallyR3) {
            tally.executeRound4(storage.getTallyR4).get
          }
        }
      }
    }
    tally
  }

  def generateDecryptionShares(encryptedUnitVectors: Map[Int, Vector[ElGamalCiphertext]], privKey: PrivKey)
                              (implicit group: DiscreteLogGroup, hash: CryptographicHash): Map[Int, DecryptionShare] = {
    encryptedUnitVectors.map { case (proposalID,v) =>
      val decryptedC1Shares = v.map { unit =>
        val decryptedC1 = unit.c1.pow(privKey).get
        val proof = ElgamalDecrNIZK.produceNIZK(unit, privKey).get
        (decryptedC1, proof)
      }
      proposalID -> DecryptionShare(proposalID, decryptedC1Shares.toSeq)
    }
  }

  def sumUpDecryptionShares(dataAll: Seq[TallyR1Data],
                            vectorSize: Int,
                            proposalIds: Seq[Int])
                           (implicit group: DiscreteLogGroup): Map[Int, Vector[GroupElement]] = {

    dataAll.foldLeft(Map[Int,Vector[GroupElement]]()) { (acc, data) =>
      proposalIds.foldLeft(acc) { (acc2, proposalId) =>
        val decryptionSharesSum = acc2.getOrElse(proposalId, Vector.fill(vectorSize)(group.groupIdentity))
        val decryptionShare = data.decryptionShares(proposalId).decryptedC1.map(_._1)
        require(decryptionSharesSum.size == decryptionShare.size)

        val newSum = decryptionSharesSum.zip(decryptionShare).map(s => s._1.multiply(s._2).get)
        acc2 + (proposalId -> newSum)
      }
    }
  }
}