package treasury.crypto

import treasury.crypto.core.Cryptosystem
import treasury.crypto.keygen._
import scala.util.Random
import treasury.crypto.core.{TimeUtils, VoteCases}

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

    val r1Data = TimeUtils.time_average_s(
      "Round 1:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR1(),
      commiteeMembersNum)

    val maxR1PacketSize = r1Data.maxBy(_.size).size
    val totalR1PacketsSize = r1Data.foldLeft(0){(totalSize, currentElement) => totalSize + currentElement.size}

    println(maxR1PacketSize + " B;\t" + totalR1PacketsSize + " B")

    val r2Data = TimeUtils.time_average_s(
      "Round 2:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR2(r1Data),
      commiteeMembersNum)

    val maxR2PacketSize = r2Data.maxBy(_.size).size
    val totalR2PacketsSize = r2Data.foldLeft(0){(totalSize, currentElement) => totalSize + currentElement.size}

    println(maxR2PacketSize + " B;\t" + totalR2PacketsSize + " B")

    val r3Data = TimeUtils.time_average_s(
      "Round 3:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR3(r2Data),
      commiteeMembersNum)

    val maxR3PacketSize = r3Data.maxBy(_.size).size
    val totalR3PacketsSize = r3Data.foldLeft(0){(totalSize, currentElement) => totalSize + currentElement.size}

    println(maxR3PacketSize + " B;\t" + totalR3PacketsSize + " B")

    val r3DataPatched = patchR3Data(cs, r3Data, violatorsNum)

    val r4Data = TimeUtils.time_average_s(
      "Round 4:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR4(r3DataPatched),
      commiteeMembersNum)

    val maxR4PacketSize = r4Data.maxBy(_.size).size
    val totalR4PacketsSize = r4Data.foldLeft(0){(totalSize, currentElement) => totalSize + currentElement.size}

    println(maxR4PacketSize + " B;\t" + totalR4PacketsSize + " B")

    val r5_1Data = TimeUtils.time_average_s(
      "Round 5.1:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR5_1(r4Data),
      commiteeMembersNum)

    val maxR5_1PacketSize = r5_1Data.maxBy(_.size).size
    val totalR5_1PacketsSize = r5_1Data.foldLeft(0){(totalSize, currentElement) => totalSize + currentElement.size}

    println(maxR5_1PacketSize + " B;\t" + totalR5_1PacketsSize + " B")

    val r5_2Data = TimeUtils.time_average_s(
      "Round 5.2:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR5_2(r5_1Data),
      commiteeMembersNum)

    val maxR5_2PacketSize = r5_2Data.maxBy(_.size).size
    val totalR5_2PacketsSize = r5_2Data.foldLeft(0){(totalSize, currentElement) => totalSize + currentElement.size}

    println(maxR5_2PacketSize + " B;\t" + totalR5_2PacketsSize + " B")

    println("------------------------")
    val overallBytes = totalR1PacketsSize + totalR2PacketsSize + totalR3PacketsSize + totalR4PacketsSize + totalR5_1PacketsSize + totalR5_2PacketsSize
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