package io.iohk.protocol.keygen

import io.iohk.core.crypto.encryption
import io.iohk.core.utils.{SizeUtils, TimeUtils}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.integration.DistributedKeyGenerationSimulator

class DistrKeyGenPerformance {

  val crs = CryptoContext.generateRandomCRS
  val ctx = new CryptoContext(Option(crs))
  import ctx.group

  def Run(commiteeMembersNum: Int, violatorsPercentage: Int): Unit = {
//    println("--------------------------------------------------------------------------------------")
//    println("Performance test")
//    println("--------------------------------------------------------------------------------------")

    val violatorsNum = (commiteeMembersNum.toFloat * (violatorsPercentage.toFloat / 100)).ceil.toInt

    println("n: " + commiteeMembersNum)
    println("t: " + violatorsNum + " (" + violatorsPercentage + "%)")
    println("------------------------")

    val keyPairs = for(id <- 1 to commiteeMembersNum) yield encryption.createKeyPair.get
    val committeeMembersPubKeys = keyPairs.map(_._2)

    val committeeMembers = for (i <- committeeMembersPubKeys.indices) yield
      new CommitteeMember(ctx, keyPairs(i), committeeMembersPubKeys)

    var overallBytes = 0

    val (r1Data, timeR1) = TimeUtils.get_time_average_s(
      "Round 1:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).doDKGRound1().get,
      commiteeMembersNum)

    overallBytes += SizeUtils.getSize(r1Data)

    val (r2Data, timeR2) = TimeUtils.get_time_average_s(
      "Round 2:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).doDKGRound2(r1Data).get,
      commiteeMembersNum)

    overallBytes += SizeUtils.getSize(r2Data)

    val (r3Data, timeR3) = TimeUtils.get_time_average_s(
      "Round 3:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).doDKGRound3(r2Data).get,
      commiteeMembersNum)

    overallBytes += SizeUtils.getSize(r3Data)

    val indexesToPatch = (0 until violatorsNum).toList
    val r3DataPatched = DistributedKeyGenerationSimulator.patchR3Data(ctx, r3Data, indexesToPatch)

    val (r4Data, timeR4) = TimeUtils.get_time_average_s(
      "Round 4:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).doDKGRound4(r3DataPatched).get,
      commiteeMembersNum)

    overallBytes += SizeUtils.getSize(r4Data)

    val (r5_1Data, timeR5_1) = TimeUtils.get_time_average_s(
      "Round 5.1:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).doDKGRound5_1(r4Data).get,
      commiteeMembersNum)

    overallBytes += SizeUtils.getSize(r5_1Data)

    val (r5_2Data, timeR5_2) = TimeUtils.get_time_average_s(
      "Round 5.2:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).doDKGRound5_2(r5_1Data).get,
      commiteeMembersNum)

    overallBytes += SizeUtils.getSize(r5_2Data)

    val overallTime = timeR1 + timeR2 + timeR3 + timeR4 + timeR5_1 + timeR5_2

    println("------------------------")
    println("Overall time:    " + overallTime + " sec")
    println("Overall traffic: " + overallBytes + " Bytes" + " (" + overallBytes / 1024 + " KB)")
    println("--------------------------------------------------------------------------------------")

    //---------------------------------------------------------------
    // Verification of the shared public key for correctness
    //---------------------------------------------------------------

    // Calculating the individual public keys (pk_i = g^sk_i for each committee)
    var individualPublicKeys = for(i <- committeeMembers.indices) yield
      (committeeMembers(i).ownId, group.groupGenerator.pow(committeeMembers(i).secretKey).get)

    val sharedPublicKeys = r5_2Data.map(_.sharedPublicKey).map(group.reconstructGroupElement(_).get)

    // Verify, that each committee has obtained the same shared public key after round 2
    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys(0))))

    // Using individual public keys to calculate the shared public key without any secret key reconstruction
    val publicKeysSum = individualPublicKeys.map(_._2).foldLeft(group.groupIdentity){(publicKeysSum, publicKey) => publicKeysSum.multiply(publicKey).get}

    // Verify, that shared public key is equal to the original public key
    assert(publicKeysSum.equals(sharedPublicKeys(0)))
  }

  def start() =
  {
    val membersNum = List(10, 20, 40, 50, 60, 80, 100)
    val violatorsPercentage = List(0, 25, 50)

    for(i <- membersNum.indices;
        j <- violatorsPercentage.indices)
      Run(membersNum(i), violatorsPercentage(j))
  }
}

object DistrKeyGenPerformance {
  def main(args: Array[String]) {
    new DistrKeyGenPerformance().start
  }
}