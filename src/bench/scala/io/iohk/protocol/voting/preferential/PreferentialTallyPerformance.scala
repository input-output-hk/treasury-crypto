package io.iohk.protocol.voting.preferential

import io.iohk.core.crypto.encryption
import io.iohk.core.utils.TimeUtils
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.integration.DistributedKeyGenerationSimulator
import io.iohk.protocol.keygen.CommitteeMember
import io.iohk.protocol.voting.preferential.tally.{PreferentialBallotsSummator, PreferentialTally}

import java.security.SecureRandom

class PreferentialTallyPerformance {
  val crs = CryptoContext.generateRandomCRS
  val ctx = new CryptoContext(Option(crs))
  import ctx.group

  def run(commiteeMembersNum: Int, violatorsPercentage: Int): Unit =
  {
    val violatorsNum = (commiteeMembersNum.toFloat * (violatorsPercentage.toFloat / 100)).ceil.toInt

    val numberOfExperts = 0
    val numberOfVoters = 500
    val stakePerVoter = 10660     // note that it is a normalized stake by dividing on granularity param. Total participating stake can be estimated as "numberOfVoters * stakePerVoter * granularity"
    val numberOfRankedProposals = 20
    val numberOfProposals = 150
    val pctx = new PreferentialContext(ctx, numberOfProposals, numberOfRankedProposals, numberOfExperts)

    println("Commitee members:\t" + commiteeMembersNum)
    println("Commitee violators:\t" + violatorsNum + " (" + violatorsPercentage + "%)")
    println("Voters: \t" + numberOfVoters)
    println("Experts:\t" + numberOfExperts)
    println("Stake per voter (normalized by granularity): \t" + stakePerVoter)
    println("Proposals: \t" + numberOfProposals)
    println("Ranked proposals:\t" + numberOfRankedProposals)
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

    val proposalIds = (0 until numberOfProposals).toList

    val summator = new PreferentialBallotsSummator(pctx)
    var voterBallotsTraffic = 0
    for (i <- 0 until numberOfVoters) {
      if (i % 100 == 0) println(i)
      val vote = scala.util.Random.shuffle(proposalIds).take(numberOfRankedProposals)
      val ballot = PreferentialVoterBallot.createBallot(pctx, DirectPreferentialVote(vote), sharedPubKey, stakePerVoter).get
      summator.addVoterBallot(ballot)
      voterBallotsTraffic += ballot.bytes.size
    }
    val expertBallots = for (i <- 0 until numberOfExperts) yield {
      val vote = scala.util.Random.shuffle(proposalIds).take(numberOfRankedProposals)
      PreferentialExpertBallot.createBallot(pctx, 0, DirectPreferentialVote(vote), sharedPubKey).get
    }

    val expertBallotsTraffic = expertBallots.headOption.map(_.bytes.size).getOrElse(0) * expertBallots.size // good enough approximation
    var overallBytes = voterBallotsTraffic + expertBallotsTraffic
    println("Voter ballots traffic: " + voterBallotsTraffic/1024 + " kB")
    println("Expert ballots traffic: " + expertBallotsTraffic/1024 + " kB\n")

    val committeeMembersActive = committeeMembersAll.drop(violatorsNum).filter(c => !dkgViolators.contains(c.publicKey))

    val tally = new PreferentialTally(pctx, committeeMembersActive.head.memberIdentifier, dkgViolators)

    val (tallyR1DataAll, timeR1) = TimeUtils.get_time_average_s(
      "Tally Round 1 (data generation):",
      committeeMembersActive.map(c => tally.generateR1Data(summator, (c.secretKey, c.publicKey)).get),
      committeeMembersActive.length
    )

    TimeUtils.time_ms("Tally Round 1 (execution):", tally.executeRound1(summator, tallyR1DataAll).get)
    val r1Traffic = tallyR1DataAll.foldLeft(0)((acc,r1Data) => acc + r1Data.bytes.size)
    overallBytes += r1Traffic
    println("Round 1 traffic: " + r1Traffic/1024 + " kB")

    val (tallyR2DataAll, timeR2) = TimeUtils.get_time_average_s(
      "Tally Round 2 (data generation):",
      committeeMembersActive.map(c => tally.generateR2Data((c.secretKey, c.publicKey), dkgR1DataAll).get),
      committeeMembersActive.length
    )

    TimeUtils.time_ms("Tally Round 2 (execution):", tally.executeRound2(tallyR2DataAll, expertBallots).get)
    val r2Traffic = tallyR2DataAll.foldLeft(0)((acc,r2Data) => acc + r2Data.bytes.size)
    overallBytes += r2Traffic
    println("Round 2 traffic: " + r2Traffic/1024 + " kB")

    val (tallyR3DataAll, timeR3) = TimeUtils.get_time_average_s(
      "Tally Round 3 (data generation):",
      committeeMembersActive.map(c => tally.generateR3Data((c.secretKey, c.publicKey)).get),
      committeeMembersActive.length
    )

    TimeUtils.time_ms("Tally Round 3 (execution):", tally.executeRound3(tallyR3DataAll).get)
    val r3Traffic = tallyR3DataAll.foldLeft(0)((acc,r3Data) => acc + r3Data.bytes.size)
    overallBytes += r3Traffic
    println("Round 3 traffic: " + r3Traffic/1024 + " kB")

    val (tallyR4DataAll, timeR4) = TimeUtils.get_time_average_s(
      "Tally Round 4 (data generation):",
      committeeMembersActive.map(c => tally.generateR4Data((c.secretKey, c.publicKey), dkgR1DataAll).get),
      committeeMembersActive.length
    )

    TimeUtils.time_ms("Tally Round 4 (execution):", tally.executeRound4(tallyR4DataAll).get)
    val r4Traffic = tallyR4DataAll.foldLeft(0)((acc,r4Data) => acc + r4Data.bytes.size)
    overallBytes += r4Traffic
    println("Round 4 traffic: " + r4Traffic/1024 + " kB")


    val overallTime = timeR1 + timeR2 + timeR3 + timeR4

    println("----------------------------------")
    println("Overall time (for one committee member):    " + overallTime + " sec")
    println("Overall traffic:                            " + overallBytes + " Bytes" + " (" + overallBytes / 1024 + " KB)")
    println("-----------------------------------")
  }

  def start() =
  {
    //val commiteeMembersNum = List(10, 25, 50, 100)
    val commiteeMembersNum = List(2)
    val violatorsPercentage = List(0)

    for(i <- commiteeMembersNum.indices;
        j <- violatorsPercentage.indices)
      run(commiteeMembersNum(i), violatorsPercentage(j))
  }
}

object PreferentialTallyPerformance {
  def main(args: Array[String]) {
    new PreferentialTallyPerformance().start
  }
}
