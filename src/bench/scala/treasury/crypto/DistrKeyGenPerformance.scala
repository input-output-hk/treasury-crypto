package treasury.crypto

import treasury.crypto.core.Cryptosystem
import treasury.crypto.keygen._

class DistrKeyGenPerformance {

  def run() = {
    println("--------------------------------------------------------------------------------------")
    println("Performance test")
    println("--------------------------------------------------------------------------------------")

    val commiteeMembersNum = 20

    println("Committee members number: " + commiteeMembersNum)

    val cs = new Cryptosystem
    val crs_h = cs.basePoint.multiply(cs.getRand)

    val minId = 1
    val maxId = 10
    val keyPairs = for(id <- minId to maxId) yield {(id, cs.createKeyPair)}

    val committeeMembersAttrs = for(i <- keyPairs.indices) yield {
      CommitteeMemberAttr(keyPairs(i)._1, keyPairs(i)._2._2)
    }

    val committeeMembers = for (i <- committeeMembersAttrs.indices) yield {

      val currentId = committeeMembersAttrs(i).id
      val currentKeyPair = keyPairs.find(_._1 == currentId).get._2

      new CommitteeMember(cs, currentId, crs_h, currentKeyPair, committeeMembersAttrs)
    }

    var t0 = System.nanoTime()
    val r1Data = for (currentId <- committeeMembersAttrs.indices) yield {
      committeeMembers(currentId).setKeyR1()
    }
    var t1 = System.nanoTime()
    println("Round 1: " + ((t1-t0).toFloat/1000000000)/commiteeMembersNum + " sec per committee member")

    t0 = System.nanoTime()
    val r2Data = for (currentId <- committeeMembersAttrs.indices) yield {
      committeeMembers(currentId).setKeyR2(r1Data)
    }
    t1 = System.nanoTime()
    println("Round 2: " + ((t1-t0).toFloat/1000000000)/commiteeMembersNum + " sec per committee member")

    t0 = System.nanoTime()
    val r3Data = for (currentId <- committeeMembersAttrs.indices) yield {
      committeeMembers(currentId).setKeyR3(r2Data)
    }
    t1 = System.nanoTime()
    println("Round 3: " + ((t1-t0).toFloat/1000000000)/commiteeMembersNum + " sec per committee member")

    t0 = System.nanoTime()
    val r4Data = for (currentId <- committeeMembersAttrs.indices) yield {
      committeeMembers(currentId).setKeyR4(r3Data)
    }
    t1 = System.nanoTime()
    println("Round 4: " + ((t1-t0).toFloat/1000000000)/commiteeMembersNum + " sec per committee member")

    t0 = System.nanoTime()
    val r5_1Data = for (currentId <- committeeMembersAttrs.indices) yield {
      committeeMembers(currentId).setKeyR5_1(r4Data)
    }
    t1 = System.nanoTime()
    println("Round 5.1: " + ((t1-t0).toFloat/1000000000)/commiteeMembersNum + " sec per committee member")

    t0 = System.nanoTime()
    val r5_2Data = for (currentId <- committeeMembersAttrs.indices) yield {
      (currentId, committeeMembers(currentId).setKeyR5_2(r5_1Data))
    }
    t1 = System.nanoTime()
    println("Round 5.2: " + ((t1-t0).toFloat/1000000000)/commiteeMembersNum + " sec per committee member")
    println("--------------------------------------------------------------------------------------")
  }
}

object DistrKeyGenPerformance {
  def main(args: Array[String]) {
    new DistrKeyGenPerformance().run
  }
}