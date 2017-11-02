package treasury.crypto

import org.scalatest.FunSuite
import treasury.crypto.keygen._

class DistrKeyGenPerformance  extends FunSuite {

    test("dkg_speed")
    {
      println("--------------------------------------------------------------------------------------")
      println("Performance test")
      println("--------------------------------------------------------------------------------------")

      val commiteeMembersNum = 20

      println("Committee members number: " + commiteeMembersNum)

      val cs = new Cryptosystem

//      val committeeMembersAttrs = (0 until commiteeMembersNum).map(new Integer(_)).map(new CommitteeMemberAttr(_, cs.basePoint.multiply(cs.getRand)))
      val committeeMembersAttrs = (0 until commiteeMembersNum).map(new Integer(_)).map(CommitteeMemberAttr(_, new Array[Byte](0)))

      val committeeMembers = for (id <- committeeMembersAttrs.indices) yield {
        new CommitteeMember(cs, id, committeeMembersAttrs)
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
