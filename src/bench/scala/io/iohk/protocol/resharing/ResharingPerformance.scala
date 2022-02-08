package io.iohk.protocol.resharing

import io.iohk.core.utils.{SizeUtils, TimeUtils}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.secret_sharing.ShamirSecretSharing.{SharingParameters, reconstructSecret}
import io.iohk.protocol.resharing.ResharingTests.{corruptResharings, generateKeys, getSharesPerParty, initialize, reshareSharesOfTheParty}

class ResharingPerformance {

  implicit private val context = new CryptoContext(None)
  import context.group

  def run(commiteeMembersNum: Int, violatorsPercentages: Seq[Int]): Unit = {

    println("n: " + commiteeMembersNum)
    println("--------------------------------------------------------------------------------------")

    val adversariesMaxNum = commiteeMembersNum / 2 - 1

    val allPartiesKeys = generateKeys(commiteeMembersNum)
    val allPartiesPubKeys = allPartiesKeys.map(_._2)
    val params = SharingParameters(allPartiesPubKeys)

    val secretsNum = 1 // commiteeMembersNum - adversariesMaxNum

    val secrets = (0 until secretsNum).indices.map(_ => group.createRandomNumber)
    val shares = getSharesPerParty(secrets, params)

    val (resharings, resharingTime) = TimeUtils.get_time_average_s(
      "Resharing round:",
      shares.zipWithIndex.map{
        case (s, i) => print(i + "\r")
          reshareSharesOfTheParty(s, params)
      },
      shares.size
    )
    val resharingsSize = SizeUtils.getSize(resharings)

    println("--------------------------------------------------------------------------------------")

    violatorsPercentages.foreach{ violatorsPercentage =>

      val violatorsNum = {
        val t = (commiteeMembersNum.toFloat * (violatorsPercentage.toFloat / 100)).floor.toInt
        if(violatorsPercentage == 50) t - 1 else t
      }
      assert(violatorsNum <= adversariesMaxNum)

      println("t: " + violatorsNum + " (" + violatorsPercentage + (if(violatorsPercentage == 50) {"% - 1)"} else {"%)"}))
      println("------------------------")

      val receivers = allPartiesKeys.map(keyPair => Resharing(context, keyPair, allPartiesPubKeys))

      var overallBytes = resharingsSize

      val corruptedResharings = corruptResharings(resharings, violatorsNum)

      val (complaints, complaintsTime) = TimeUtils.get_time_average_s(
        "Complaints round:",
        receivers.zipWithIndex.flatMap{
          case (r, i) => print(i + "\r")
            r.receiveResharings(corruptedResharings)
        },
        receivers.size
      )
      overallBytes = overallBytes + SizeUtils.getSize(complaints)

      // The newly built shares are not posted so not accounting them in overall traffic
      // No need to run 'buildNewShares' for all receivers due to the running time is the same for all of them
      val (_, sharesBuildingTime) = TimeUtils.get_time_average_s(
        "New shares calculation:",
        receivers.head.buildNewShares(complaints), 1
      )

      val overallTime = resharingTime + complaintsTime + sharesBuildingTime

      println
      println("------------------------")
      println("Overall time:    " + overallTime + " sec")
      println("Overall traffic: " + overallBytes + " Bytes" + " (" + overallBytes / 1024 + " KB)")
      println("--------------------------------------------------------------------------------------")
    }
  }

  def start(): Unit =
  {
    val membersNum =  List(10, 20, 40, 60, 80, 100)
    val violatorsPercentages = List(0, 25, 50)

    for(i <- membersNum.indices)
      run(membersNum(i), violatorsPercentages)
  }
}


object ResharingPerformance {
  def main(args: Array[String]) {
    new ResharingPerformance().start()
  }
}
