package io.iohk.protocol.voting.approval.multi_delegation

import io.iohk.core.crypto.encryption
import io.iohk.core.utils.TimeUtils
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.integration.DistributedKeyGenerationSimulator
import io.iohk.protocol.keygen._
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.multi_delegation.tally.{MultiDelegBallotsSummator, MultiDelegTally}

class MultiDelegTallyPerformance {

  val crs = CryptoContext.generateRandomCRS
  val ctx = new CryptoContext(Option(crs))
  import ctx.group

  def run(commiteeMembersNum: Int, violatorsPercentage: Int): Unit =
  {
    val violatorsNum = (commiteeMembersNum.toFloat * (violatorsPercentage.toFloat / 100)).ceil.toInt

    val numberOfExperts = 0
    val numberOfVoters = 5000
    val stakePerVoter = 1066     // note that it is a normalized stake by dividing on granularity param. Total participating stake can be estimated as "numberOfVoters * stakePerVoter * granularity"
    val numberOfProposals = 1   // note that all numbers (traffic, tally time) grows linearly with the number of proposals, so we can just multiply benchmarks to the number of proposals to get estimated values for many proposals
    val numberOfChoices = 3

    val pctx = new ApprovalContext(ctx, numberOfChoices, numberOfExperts, numberOfProposals)

    println("Commitee members:\t" + commiteeMembersNum)
    println("Commitee violators:\t" + violatorsNum + " (" + violatorsPercentage + "%)")
    println("Voters: \t" + numberOfVoters)
    println("Experts:\t" + numberOfExperts)
    println("Stake per voter (normalized by granularity): \t" + stakePerVoter)
    println("Proposals: \t" + numberOfProposals)
    println("Number of choices: \t" + numberOfChoices)
    println("------------------------")

    // Generating keypairs for every commitee member
    val keyPairs = for(id <- 1 to commiteeMembersNum) yield encryption.createKeyPair.get
    val committeeMembersPubKeys = keyPairs.map(_._2)

    // Instantiating committee members
    //
    val committeeMembersAll = for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(ctx, keyPairs(i), committeeMembersPubKeys)
    }

    // Generating shared public key by committee members (by running the DKG protocol between them)
    val (sharedPubKey, dkgR1DataAll, dkgViolators) = DistributedKeyGenerationSimulator.runDKG(ctx, committeeMembersAll)

    val voterBallots = for (i <- 0 until numberOfVoters) yield
      MultiDelegPublicStakeBallot.createBallot(pctx, 0, DirectMultiDelegVote(0), sharedPubKey, stakePerVoter).get
    val expertBallots = for (i <- 0 until numberOfExperts) yield
      MultiDelegExpertBallot.createBallot(pctx, 0, 0, DirectMultiDelegVote(0), sharedPubKey).get

    var overallBytes: Int = 0
    val voterBallotsTraffic = voterBallots.headOption.map(_.bytes.size).getOrElse(0) * voterBallots.size // good enough approximation
    val expertBallotsTraffic = expertBallots.headOption.map(_.bytes.size).getOrElse(0) * expertBallots.size
    overallBytes += voterBallotsTraffic + expertBallotsTraffic
    println("Voter ballots traffic: " + voterBallotsTraffic/1024 + " kB")
    println("Expert ballots traffic: " + expertBallotsTraffic/1024 + " kB\n")

    val committeeMembersActive = committeeMembersAll.drop(violatorsNum).filter(c => !dkgViolators.contains(c.publicKey))

    val summator = new MultiDelegBallotsSummator(pctx)
    voterBallots.foreach(summator.addVoterBallot(_))

    val tally = new MultiDelegTally(pctx, committeeMembersActive.head.memberIdentifier, dkgViolators)

    val (tallyR1DataAll, timeR1) = TimeUtils.get_time_average_s(
      "Tally Round 1 (data generation):",
      committeeMembersActive.map(c => tally.generateR1Data(summator, (c.secretKey, c.publicKey)).get),
      committeeMembersActive.length
    )

    TimeUtils.time_ms("Tally Round 1 (execution):", tally.executeRound1(summator, tallyR1DataAll).get)
    overallBytes += tallyR1DataAll.foldLeft(0)((acc,r1Data) => acc + r1Data.bytes.size)

    val (tallyR2DataAll, timeR2) = TimeUtils.get_time_average_s(
      "Tally Round 2 (data generation):",
      committeeMembersActive.map(c => tally.generateR2Data((c.secretKey, c.publicKey), dkgR1DataAll).get),
      committeeMembersActive.length
    )

    TimeUtils.time_ms("Tally Round 2 (execution):", tally.executeRound2(tallyR2DataAll, expertBallots).get)
    overallBytes += tallyR2DataAll.foldLeft(0)((acc,r2Data) => acc + r2Data.bytes.size)

    val (tallyR3DataAll, timeR3) = TimeUtils.get_time_average_s(
      "Tally Round 3 (data generation):",
      committeeMembersActive.map(c => tally.generateR3Data((c.secretKey, c.publicKey)).get),
      committeeMembersActive.length
    )

    TimeUtils.time_ms("Tally Round 3 (execution):", tally.executeRound3(tallyR3DataAll).get)
    overallBytes += tallyR3DataAll.foldLeft(0)((acc,r3Data) => acc + r3Data.bytes.size)

    val (tallyR4DataAll, timeR4) = TimeUtils.get_time_average_s(
      "Tally Round 4 (data generation):",
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
    //val commiteeMembersNum = List(10, 20, 40, 50, 60, 80, 100)
    //val violatorsPercentage = List(0, 25, 50)
    val commiteeMembersNum = List(2)
    val violatorsPercentage = List(0)

    for(i <- commiteeMembersNum.indices;
        j <- violatorsPercentage.indices)
      run(commiteeMembersNum(i), violatorsPercentage(j))
  }
}

object MultiDelegTallyPerformance {
  def main(args: Array[String]) {
    new MultiDelegTallyPerformance().start
  }
}