package treasury.crypto

import treasury.crypto.core.Cryptosystem
import treasury.crypto.keygen._
import scala.util.Random
import treasury.crypto.core.{TimeUtils, VoteCases}

class DistrKeyGenPerformance {

  def patchR3Data(cs: Cryptosystem, r3Data: Seq[R3Data], numOfPatches: Int): Seq[R3Data] =
  {
    assert(numOfPatches <= r3Data.length)

    var r3DataPatched = r3Data

    var indexesToPatch = Array.fill[Boolean](numOfPatches)(true) ++ Array.fill[Boolean](r3Data.length - numOfPatches)(false)
    indexesToPatch = Random.shuffle(indexesToPatch.toSeq).toArray

    for(i <- r3Data.indices)
      if(indexesToPatch(i))
        r3DataPatched(i).commitments(0) = cs.infinityPoint.getEncoded(true)

    r3DataPatched
  }

  def run(): Unit = {
    println("--------------------------------------------------------------------------------------")
    println("Performance test")
    println("--------------------------------------------------------------------------------------")

    val commiteeMembersNum = 200
    val violatorsPercentage = 50
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

    val r2Data = TimeUtils.time_average_s(
      "Round 2:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR2(r1Data),
      commiteeMembersNum)

    val r3Data = TimeUtils.time_average_s(
      "Round 3:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR3(r2Data),
      commiteeMembersNum)

    val r3DataPatched = patchR3Data(cs, r3Data, violatorsNum)

    val r4Data = TimeUtils.time_average_s(
      "Round 4:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR4(r3DataPatched),
      commiteeMembersNum)

    val r5_1Data = TimeUtils.time_average_s(
      "Round 5.1:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR5_1(r4Data),
      commiteeMembersNum)

    val r5_2Data = TimeUtils.time_average_s(
      "Round 5.2:",
      for (i <- 0 until commiteeMembersNum) yield committeeMembers(i).setKeyR5_2(r5_1Data),
      commiteeMembersNum)

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
}

object DistrKeyGenPerformance {
  def main(args: Array[String]) {
    new DistrKeyGenPerformance().run
  }
}