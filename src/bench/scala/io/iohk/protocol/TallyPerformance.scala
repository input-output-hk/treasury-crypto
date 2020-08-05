package io.iohk.protocol

import io.iohk.core.crypto.encryption
import io.iohk.core.utils.TimeUtils
import io.iohk.protocol.integration.ProtocolTest
import io.iohk.protocol.keygen._
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.approval.multi_delegation.approval.{DelegatedVote, DirectVote}
import io.iohk.protocol.voting.approval.multi_delegation.{ExpertBallot, PublicStakeBallot}

class TallyPerformance {

  val crs = CryptoContext.generateRandomCRS
  val ctx = new CryptoContext(Option(crs))
  import ctx.group

  def run(commiteeMembersNum: Int, violatorsPercentage: Int): Unit =
  {
    val violatorsNum = (commiteeMembersNum.toFloat * (violatorsPercentage.toFloat / 100)).ceil.toInt

    val numberOfExperts = 100
    val numberOfVoters = 1000
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
    val (sharedPubKey, dkgR1DataAll) = ProtocolTest.runDistributedKeyGeneration(ctx, committeeMembersAll)

    val voterBallots = for (i <- 0 until numberOfVoters) yield
      PublicStakeBallot.createBallot(pctx, 0, DelegatedVote(0), sharedPubKey, 1).get
    val expertBallots = for (i <- 0 until numberOfExperts) yield
      ExpertBallot.createBallot(pctx, 0, 0, DirectVote(0), sharedPubKey).get

    var overallBytes: Int = 0
    val committeeMembersActive = committeeMembersAll.drop(violatorsNum)

    val (tallyR1DataAll, timeR1) = TimeUtils.get_time_average_s(
      "Tally Round 1:",
      committeeMembersActive.map(_.doTallyR1(voterBallots).get),
      committeeMembersActive.length
    )

    overallBytes += tallyR1DataAll.foldLeft(0)((acc,r1Data) => acc + r1Data.bytes.size)

    val (tallyR2DataAll, timeR2) = TimeUtils.get_time_average_s(
      "Tally Round 2:",
      committeeMembersActive.map(_.doTallyR2(tallyR1DataAll, dkgR1DataAll).get),
      committeeMembersActive.length
    )

    overallBytes += tallyR2DataAll.foldLeft(0)((acc,r2Data) => acc + r2Data.bytes.size)

    val (tallyR3DataAll, timeR3) = TimeUtils.get_time_average_s(
      "Tally Round 3:",
      committeeMembersActive.map(_.doTallyR3(tallyR2DataAll, dkgR1DataAll, expertBallots).get),
      committeeMembersActive.length
    )

    overallBytes += tallyR3DataAll.foldLeft(0)((acc,r3Data) => acc + r3Data.bytes.size)

    val (tallyR4DataAll, timeR4) = TimeUtils.get_time_average_s(
      "Tally Round 4:",
      committeeMembersActive.map(_.doTallyR4(tallyR3DataAll, dkgR1DataAll).get),
      committeeMembersActive.length
    )

    overallBytes += tallyR4DataAll.foldLeft(0)((acc,r4Data) => acc + r4Data.bytes.size)

    val (tallyResults, timeFinalize) = TimeUtils.get_time_average_s(
      "Tally Finalize:",
      committeeMembersActive.map(_.finalizeTally(tallyR4DataAll, dkgR1DataAll).get),
      committeeMembersActive.length
    )

    val overallTime = timeR1 + timeR2 + timeR3 + timeR4 + timeFinalize

    println("----------------------------------")
    println("Overall time (for one committee member):    " + overallTime + " sec")
    println("Overall traffic:                            " + overallBytes + " Bytes" + " (" + overallBytes / 1024 + " KB)")
    println("-----------------------------------")

    assert(tallyResults.forall(_.equals(tallyResults.head)))
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