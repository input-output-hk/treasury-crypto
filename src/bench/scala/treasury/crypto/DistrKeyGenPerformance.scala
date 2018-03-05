package treasury.crypto

import treasury.crypto.core.{Cryptosystem, SizeUtils, TimeUtils}
import treasury.crypto.keygen._

class DistrKeyGenPerformance {

  def Run(commiteeMembersNum: Int, violatorsPercentage: Int): Unit = {
//    println("--------------------------------------------------------------------------------------")
//    println("Performance test")
//    println("--------------------------------------------------------------------------------------")

    val violatorsNum = (commiteeMembersNum.toFloat * (violatorsPercentage.toFloat / 100)).ceil.toInt

    println("n: " + commiteeMembersNum)
    println("t: " + violatorsNum + " (" + violatorsPercentage + "%)")
    println("------------------------")

    val cs = new Cryptosystem
    val crs_h = cs.basePoint.multiply(cs.getRand)

    val keyPairs = for(id <- 1 to commiteeMembersNum) yield cs.createKeyPair
    val committeeMembersPubKeys = keyPairs.map(_._2)

    val committeeMembers = for (i <- committeeMembersPubKeys.indices) yield
      new CommitteeMember(cs, crs_h, keyPairs(i), committeeMembersPubKeys)

    var overallBytes = 0

    val (r1Data, timeR1) = TimeUtils.get_time_average_s(
      "Round 1:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR1(),
      commiteeMembersNum)

    overallBytes += SizeUtils.getSize(r1Data)

    val (r2Data, timeR2) = TimeUtils.get_time_average_s(
      "Round 2:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR2(r1Data),
      commiteeMembersNum)

    overallBytes += SizeUtils.getSize(r2Data)

    val (r3Data, timeR3) = TimeUtils.get_time_average_s(
      "Round 3:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR3(r2Data),
      commiteeMembersNum)

    overallBytes += SizeUtils.getSize(r3Data)

    val r3DataPatched = patchR3Data(cs, r3Data, violatorsNum)

    val (r4Data, timeR4) = TimeUtils.get_time_average_s(
      "Round 4:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR4(r3DataPatched),
      commiteeMembersNum)

    overallBytes += SizeUtils.getSize(r4Data)

    val (r5_1Data, timeR5_1) = TimeUtils.get_time_average_s(
      "Round 5.1:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR5_1(r4Data),
      commiteeMembersNum)

    overallBytes += SizeUtils.getSize(r5_1Data)

    val (r5_2Data, timeR5_2) = TimeUtils.get_time_average_s(
      "Round 5.2:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR5_2(r5_1Data),
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
      (committeeMembers(i).ownId, cs.basePoint.multiply(committeeMembers(i).secretKey))

    val sharedPublicKeys = r5_2Data.map(_.sharedPublicKey).map(cs.decodePoint)

    // Verify, that each committee has obtained the same shared public key after round 2
    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys(0))))

    // Using individual public keys to calculate the shared public key without any secret key reconstruction
    val publicKeysSum = individualPublicKeys.map(_._2).foldLeft(cs.infinityPoint){(publicKeysSum, publicKey) => publicKeysSum.add(publicKey)}

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