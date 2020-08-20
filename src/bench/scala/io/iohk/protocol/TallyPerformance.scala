package io.iohk.protocol

import io.iohk.core.crypto.encryption
import io.iohk.core.utils.TimeUtils
import io.iohk.protocol.integration.{DistributedKeyGenerationSimulator, ProtocolTest}
import io.iohk.protocol.keygen._
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.multi_delegation.tally.{MultiDelegBallotsSummator, MultiDelegTally}
import io.iohk.protocol.voting.approval.multi_delegation.{DelegatedMultiDelegVote, DirectMultiDelegVote, MultiDelegExpertBallot, MultiDelegPublicStakeBallot}

class TallyPerformance {

  val crs = CryptoContext.generateRandomCRS
  val ctx = new CryptoContext(Option(crs))
  import ctx.group

  def run(commiteeMembersNum: Int, violatorsPercentage: Int): Unit =
  {
    val violatorsNum = (commiteeMembersNum.toFloat * (violatorsPercentage.toFloat / 100)).ceil.toInt

    val numberOfExperts = 10
    val numberOfVoters = 100
    val pctx = new ApprovalContext(ctx, 3, numberOfExperts)

    println("Commitee members:\t" + commiteeMembersNum)
    println("Commitee violators:\t" + violatorsNum + " (" + violatorsPercentage + "%)")
    println("Voters: \t" + numberOfVoters)
    println("Experts:\t" + numberOfExperts)
    println("------------------------")

    // Generating keypairs for every commitee member
    val keyPairs = for(id <- 1 to commiteeMembersNum) yield encryption.createKeyPair.get
    val committeeMembersPubKeys = keyPairs.map(_._2)

    // Instantiating committee members
    //
    val committeeMembersAll = for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(pctx, keyPairs(i), committeeMembersPubKeys)
    }

    // Generating shared public key by committee members (by running the DKG protocol between them)
    val (sharedPubKey, dkgR1DataAll, dkgViolators) = DistributedKeyGenerationSimulator.runDKG(ctx, committeeMembersAll)

    val voterBallots = for (i <- 0 until numberOfVoters) yield
      MultiDelegPublicStakeBallot.createBallot(pctx, 0, DelegatedMultiDelegVote(0), sharedPubKey, 1).get
    val expertBallots = for (i <- 0 until numberOfExperts) yield
      MultiDelegExpertBallot.createBallot(pctx, 0, 0, DirectMultiDelegVote(0), sharedPubKey).get

    var overallBytes: Int = 0
    val committeeMembersActive = committeeMembersAll.drop(violatorsNum).filter(c => !dkgViolators.contains(c.publicKey))

    val context = new ApprovalContext(ctx, 3, numberOfExperts, 1)
    val summator = new MultiDelegBallotsSummator(context)
    voterBallots.foreach(summator.addVoterBallot(_))

    val tally = new MultiDelegTally(context, committeeMembersActive.head.memberIdentifier, dkgViolators)

    val (tallyR1DataAll, timeR1) = TimeUtils.get_time_average_s(
      "Tally Round 1 (ballot generation):",
      committeeMembersActive.map(c => tally.generateR1Data(summator, (c.secretKey, c.publicKey)).get),
      committeeMembersActive.length
    )

    TimeUtils.time_ms("Tally Round 1 (execution):", tally.executeRound1(summator, tallyR1DataAll).get)
    overallBytes += tallyR1DataAll.foldLeft(0)((acc,r1Data) => acc + r1Data.bytes.size)

    val (tallyR2DataAll, timeR2) = TimeUtils.get_time_average_s(
      "Tally Round 2 (ballot generation):",
      committeeMembersActive.map(c => tally.generateR2Data((c.secretKey, c.publicKey), dkgR1DataAll).get),
      committeeMembersActive.length
    )

    TimeUtils.time_ms("Tally Round 2 (execution):", tally.executeRound2(tallyR2DataAll, expertBallots).get)
    overallBytes += tallyR2DataAll.foldLeft(0)((acc,r2Data) => acc + r2Data.bytes.size)

    val (tallyR3DataAll, timeR3) = TimeUtils.get_time_average_s(
      "Tally Round 3 (ballot generation):",
      committeeMembersActive.map(c => tally.generateR3Data((c.secretKey, c.publicKey)).get),
      committeeMembersActive.length
    )

    TimeUtils.time_ms("Tally Round 3 (execution):", tally.executeRound3(tallyR3DataAll).get)
    overallBytes += tallyR3DataAll.foldLeft(0)((acc,r3Data) => acc + r3Data.bytes.size)

    val (tallyR4DataAll, timeR4) = TimeUtils.get_time_average_s(
      "Tally Round 4 (ballot generation):",
      committeeMembersActive.map(c => tally.generateR4Data((c.secretKey, c.publicKey), dkgR1DataAll).get),
      committeeMembersActive.length
    )

    TimeUtils.time_ms("Tally Round 4 (execution):", tally.executeRound4(tallyR4DataAll).get)
    overallBytes += tallyR4DataAll.foldLeft(0)((acc,r4Data) => acc + r4Data.bytes.size)


    val overallTime = timeR1 + timeR2 + timeR3 + timeR4

    println("----------------------------------")
    println("Overall time (for one committee member):    " + overallTime + " sec")
    println("Overall traffic:                            " + overallBytes + " Bytes" + " (" + overallBytes / 1024 + " KB)")
    println("-----------------------------------")
  }

  def start() =
  {
    val commiteeMembersNum = List(10, 20, 40, 50, 60, 80, 100)
    val violatorsPercentage = List(0, 25, 50)

    for(i <- commiteeMembersNum.indices;
        j <- violatorsPercentage.indices)
      run(commiteeMembersNum(i), violatorsPercentage(j))
  }
}

object TallyPerformance {
  def main(args: Array[String]) {
    new TallyPerformance().start
  }
}