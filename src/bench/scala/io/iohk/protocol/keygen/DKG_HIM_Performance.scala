package io.iohk.protocol.keygen

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.core.utils.{SizeUtils, TimeUtils}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_him.DKGenerator
import io.iohk.protocol.keygen_him.datastructures.R2Data

class DKG_HIM_Performance {
  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val g = context.group.groupGenerator

  import context.group

  def generateKeys(num: Int) : Seq[KeyPair] = for (_ <- 0 until num) yield encryption.createKeyPair(context.group).get

  def corruptR2Data(r2Data: Seq[R2Data], numOfPartiesToCorrupt: Int): Seq[R2Data] = {
    assert(numOfPartiesToCorrupt <= r2Data.length)
    r2Data.zipWithIndex.map{
      case (d, i) =>
        if (i < numOfPartiesToCorrupt){
          R2Data(
            d.senderID,
            d.coeffsCommitments.drop(1) // removing the R2-commitment of a_0 coefficient for a specified party
          )
        } else { d }
    }
  }

  def run(commiteeMembersNum: Int, violatorsPercentage: Int = 0): Unit = {

    val violatorsNum = {
      val t = (commiteeMembersNum.toFloat * (violatorsPercentage.toFloat / 100)).floor.toInt
      if(violatorsPercentage == 50) t - 1 else t
    }

    println("n: " + commiteeMembersNum)
    println("t: " + violatorsNum + " (" + violatorsPercentage + (if(violatorsPercentage == 50) {"% - 1)"} else {"%)"}))
    println("------------------------")

    val generatorsKeys = generateKeys(commiteeMembersNum)
    val generatedKeysNum = commiteeMembersNum / 2 + 1

    val alphas = (0 until commiteeMembersNum).map(_ => group.createRandomNumber)
    val betas  = (0 until generatedKeysNum).map(_ => group.createRandomNumber)

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
      generators.zipWithIndex.map{
        case (g, i) => print(i + "\r")
          g.round1()
      },
      generators.size
    )
    overallBytes = overallBytes + SizeUtils.getSize(r1Data)

    val (r2Data, timeR2) = TimeUtils.get_time_average_s(
      "Round 2:",
      generators.zipWithIndex.map{
        case (g, i) => print(i + "\r")
          g.round2(r1Data)
      },
      generators.size
    )
    overallBytes = overallBytes + SizeUtils.getSize(r2Data)

    val (r3Data, timeR3) = TimeUtils.get_time_average_s(
      "Round 3:",
      generators.zipWithIndex.flatMap{
        case (g, i) => print(i + "\r")
          g.round3(corruptR2Data(r2Data, violatorsNum))
      },
      generators.size
    )
    overallBytes = overallBytes + SizeUtils.getSize(r3Data)

    val (r4Data, timeR4) = TimeUtils.get_time_average_s(
      "Round 4:",
      generators.zipWithIndex.map{
        case (g, i) => print(i + "\r")
          g.round4(r3Data)
      },
      generators.size
    )
    overallBytes = overallBytes + SizeUtils.getSize(r4Data)

    val overallTime = timeR1 + timeR2 + timeR3 + timeR4

    println
    println("------------------------")
    println("Overall time:    " + overallTime + " sec")
    println("Overall traffic: " + overallBytes + " Bytes" + " (" + overallBytes / 1024 + " KB)")
    println("--------------------------------------------------------------------------------------")
  }

  def start(): Unit =
  {
    val membersNum = List(10, 20, 40, 60, 80, 100)
    val violatorsPercentage = List(0, 25, 50)

    for(i <- membersNum.indices;
        j <- violatorsPercentage.indices)
      run(membersNum(i), violatorsPercentage(j))

//    val membersNum = List(5, 10, 20, 40)
//    val membersNum = List(80)
//    membersNum.foreach(run(_))
  }
}


object DKG_HIM_Performance {
  def main(args: Array[String]) {
    new DKG_HIM_Performance().start()
  }
}