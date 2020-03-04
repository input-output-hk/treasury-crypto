package io.iohk

import io.iohk.common.VotingSimulator
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import io.iohk.core.utils.{SizeUtils, TimeUtils}
import io.iohk.protocol.Cryptosystem
import io.iohk.protocol.keygen._

class TallyPerformance {

  implicit val group = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256r1).get
  implicit val hash = CryptographicHashFactory.constructHash(AvailableHashes.SHA3_256_Bc).get

  def run(commiteeMembersNum: Int, violatorsPercentage: Int): Unit =
  {
    val violatorsNum = (commiteeMembersNum.toFloat * (violatorsPercentage.toFloat / 100)).ceil.toInt

    val numberOfExperts = 100
    val numberOfVoters = 1000

    println("Commitee members:\t" + commiteeMembersNum)
    println("Commitee violators:\t" + violatorsNum + " (" + violatorsPercentage + "%)")
    println("Voters: \t" + numberOfVoters)
    println("Experts:\t" + numberOfExperts)
    println("------------------------")

    val cs = new Cryptosystem
    val crs_h = cs.basePoint.pow(cs.getRand).get

    // Generating keypairs for every commitee member
    val keyPairs = for(id <- 1 to commiteeMembersNum) yield cs.createKeyPair
    val committeeMembersPubKeys = keyPairs.map(_._2)

    // Instantiating committee members
    //
    val committeeMembers = for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(cs, crs_h, keyPairs(i), committeeMembersPubKeys)
    }

    // Generating shared public key by committee members (by running the DKG protocol between them)
    val sharedPubKey = getSharedPublicKey(cs, committeeMembers)

    val ballots = new VotingSimulator(commiteeMembersNum, numberOfExperts, numberOfVoters, 1, false, Some(sharedPubKey)).prepareBallots()

    val R1_ABSENTEES_NUM = violatorsNum / 2
    val R2_ABSENTEES_NUM = violatorsNum - R1_ABSENTEES_NUM

    val committeeMembersR1 = committeeMembers.take(committeeMembers.length - R1_ABSENTEES_NUM)
    val committeeMembersR2 = committeeMembersR1.take(committeeMembersR1.length - R2_ABSENTEES_NUM)

    var overallBytes = 0

    val (decryptedC1ForDelegations, timeR1) = TimeUtils.get_time_average_s(
      "Round 1:",
      committeeMembersR1.map(_.decryptTallyR1(ballots)),
      committeeMembersR1.length
    )

    overallBytes += SizeUtils.getSize(decryptedC1ForDelegations)

    val (skSharesR1, timeRecovery1) = TimeUtils.get_time_average_s(
      "Recovery 1:",
      committeeMembersR1.map(_.keysRecoveryR1(decryptedC1ForDelegations)),
      committeeMembersR1.length
    )

    overallBytes += SizeUtils.getSize(skSharesR1)

    val (decryptedC1ForChoices, timeR2) = TimeUtils.get_time_average_s(
      "Round 2:",
      committeeMembersR2.map(_.decryptTallyR2(decryptedC1ForDelegations, skSharesR1)),
      committeeMembersR2.length
    )

    overallBytes += SizeUtils.getSize(decryptedC1ForChoices)

    val (skSharesR2, timeRecovery2) = TimeUtils.get_time_average_s(
      "Recovery 2:",
      committeeMembersR2.map(_.keysRecoveryR2(decryptedC1ForChoices)),
      committeeMembersR2.length
    )

    overallBytes += SizeUtils.getSize(skSharesR2)

    val (tallyResults, timeR3) = TimeUtils.get_time_average_s(
      "Round 3:",
      committeeMembersR2.map(_.decryptTallyR3(decryptedC1ForDelegations, skSharesR1, skSharesR2)),
      committeeMembersR2.length
    )

    val overallTime = timeR1 + timeRecovery1 + timeR2 + timeRecovery2 + timeR3

    println("----------------------------------")
    println("Overall time:    " + overallTime + " sec")
    println("Overall traffic: " + overallBytes + " Bytes" + " (" + overallBytes / 1024 + " KB)")
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