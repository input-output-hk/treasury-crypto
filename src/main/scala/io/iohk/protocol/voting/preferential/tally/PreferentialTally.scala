package io.iohk.protocol.voting.preferential.tally

import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.core.crypto.primitives.dlog.{DiscreteLogGroup, GroupElement}
import io.iohk.protocol.Identifier
import io.iohk.protocol.nizk.ElgamalDecrNIZK
import io.iohk.protocol.tally.{BallotsSummator, Tally}
import io.iohk.protocol.tally.Tally.Stages
import io.iohk.protocol.tally.datastructures.TallyR1Data
import io.iohk.protocol.voting.preferential.PreferentialContext
import io.iohk.protocol.voting.preferential.tally.datastructures.PrefTallyR1Data

import scala.util.Try

class PreferentialTally(ctx: PreferentialContext,
                        cmIdentifier: Identifier[Int],
                        disqualifiedBeforeTallyCommitteeKeys: Map[PubKey, Option[PrivKey]]) {
  import ctx.cryptoContext.{group, hash}

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
    if (currentRound != Stages.Init)
      throw new IllegalStateException("Unexpected state! Round 1 should be executed only in the Init state.")

    if (ctx.numberOfExperts <= 0) {
      // there is nothing to do on Round 1 if there are no experts or no proposals
      currentRound = Stages.TallyR1
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
    currentRound = Stages.TallyR1
    this
  }
}

object PreferentialTally {

}