package io.iohk.protocol.keygen

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.core.utils.{SizeUtils, TimeUtils}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_him.DKGenerator

class DKG_HIM_Performance {
  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val g = context.group.groupGenerator

  import context.group

  def generateKeys(num: Int) : Seq[KeyPair] = for (_ <- 0 until num) yield encryption.createKeyPair(context.group).get

  def run(commiteeMembersNum: Int, violatorsPercentage: Int = 0): Unit = {
    println("Generators: " + commiteeMembersNum)

    val generatorsKeys = generateKeys(commiteeMembersNum)

    val alphas = generatorsKeys.map(_ => group.createRandomNumber)
    val betas  = generatorsKeys.map(_ => group.createRandomNumber)

    val generators = generatorsKeys.map(keyPair =>
      DKGenerator(
        context,
        Seq(crs),
        keyPair,
        generatorsKeys.map(_._2),
        alphas,
        betas
      )
    )

    var overallBytes = 0

    val (r1Data, timeR1) = TimeUtils.get_time_average_s(
      "Round 1:",
      generators.zipWithIndex.map{case (g, i) => print(i + "\r"); g.round1()},
      generators.size
    )
    overallBytes = overallBytes + SizeUtils.getSize(r1Data)

    val (r2Data, timeR2) = TimeUtils.get_time_average_s(
      "Round 2:",
      generators.zipWithIndex.map{case (g, i) => print(i + "\r"); g.round2(r1Data)},
      generators.size
    )
    overallBytes = overallBytes + SizeUtils.getSize(r2Data)

    val (complaints, timeComplaints) = TimeUtils.get_time_average_s(
      "Round 3:",
      generators.map(_.round3(r2Data)),
      generators.size
    )
    assert(complaints.forall(_.isEmpty))
//    overallBytes = overallBytes + SizeUtils.getSize(complaints)

    val overallTime = timeR1 + timeR2 + timeComplaints

    println
    println("------------------------")
    println("Overall time:    " + overallTime + " sec")
    println("Overall traffic: " + overallBytes + " Bytes" + " (" + overallBytes / 1024 + " KB)")
    println("--------------------------------------------------------------------------------------")
  }

  def start(): Unit =
  {
//    val membersNum = List(10, 20, 40, 60, 80, 100)
//    val violatorsPercentage = List(0, 25, 50)
//
//    for(i <- membersNum.indices;
//        j <- violatorsPercentage.indices)
//      run(membersNum(i), violatorsPercentage(j))

//    val membersNum = List(5, 10, 20, 40)
    val membersNum = List(80)
    membersNum.foreach(run(_))
  }
}


object DKG_HIM_Performance {
  def main(args: Array[String]) {
    new DKG_HIM_Performance().start()
  }
}