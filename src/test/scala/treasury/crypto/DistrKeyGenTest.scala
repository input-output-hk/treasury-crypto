package treasury.crypto
import java.security.Security
import java.math.BigInteger

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.scalatest.FunSuite
import java.util.Random

import treasury.crypto.keygen.{CommitteeMember, CommitteeMemberAttr,R1Data, R3Data}

class DistrKeyGenTest  extends FunSuite {

  test("dkg_functionality"){
    val cs = new Cryptosystem
    val crs_h = cs.basePoint.multiply(cs.getRand)

    val committeeMembersAttrs = (0 to 5).map(new Integer(_)).map(new CommitteeMemberAttr(_, cs.basePoint.multiply(cs.getRand)))

    val committeeMembers = for (id <- committeeMembersAttrs.indices) yield {
      new CommitteeMember(cs, id, crs_h, committeeMembersAttrs)
    }

    var r1Data = for (currentId <- committeeMembersAttrs.indices) yield {
      committeeMembers(currentId).setKeyR1()
    }

    // Changing commitments of some committee members to get complain on them
    //
    r1Data.map
    {
      (x) =>
      {
        val E = x.E
//        if(rand.nextBoolean())
        if(x.issuerID == 0)
        {
          println(x.issuerID + " committee members's commitment modified on Round 2")
          E(0) = cs.infinityPoint.getEncoded(true)
        }
        R1Data(x.issuerID, E, x.S_a, x.S_b)
      }
    }

    val r2Data = for (currentId <- committeeMembersAttrs.indices) yield {
      committeeMembers(currentId).setKeyR2(r1Data)
    }

    val r3Data = for (currentId <- committeeMembersAttrs.indices) yield {
      committeeMembers(currentId).setKeyR3(r2Data)
    }

    // Changing commitments of some committee members to get complain on them
    //
    r3Data.map
    {
      (x) =>
      {
        val commitments = x.commitments
//        if(rand.nextBoolean())
        if(x.issuerID == 1)
        {
          println(x.issuerID + " committee members's commitment modified on Round 3")
          commitments(0) = cs.infinityPoint.getEncoded(true)
        }
        R3Data(x.issuerID, commitments)
      }
    }

    val r4Data = for (currentId <- committeeMembersAttrs.indices) yield {
      committeeMembers(currentId).setKeyR4(r3Data)
    }

    val r5_1Data = for (currentId <- committeeMembersAttrs.indices) yield {
      committeeMembers(currentId).setKeyR5_1(r4Data)
    }

    val sharedPublicKeys = for (currentId <- committeeMembersAttrs.indices) yield {
      (currentId, committeeMembers(currentId).setKeyR5_2(r5_1Data))
    }

    //---------------------------------------------------------------
    // Verification of the shared public key for correctness
    //---------------------------------------------------------------

    // Calculating the individual public keys (pk_i = g^sk_i for each committee)
    var individualPublicKeys = for(i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownID, cs.basePoint.multiply(committeeMembers(i).secretKey))
    }

    var sharedPublicKeysAfterR2 = sharedPublicKeys

    // Violators detected on the 2-nd round doesn't participate in the shared public key generation at all
    for(i <- r2Data.indices)
    {
      for(j <- r2Data(i).complains.indices)
      {
        val violatorID = r2Data(i).complains(j).violatorID

        individualPublicKeys = individualPublicKeys.filter(_._1 != violatorID)
        sharedPublicKeysAfterR2 = sharedPublicKeys.filter(_._1 != violatorID)
      }
    }

    // Verify, that each committee has obtained the same shared public key after round 2
    assert(sharedPublicKeysAfterR2.map(_._2).forall(cs.decodePoint(_).equals(cs.decodePoint(sharedPublicKeysAfterR2(0)._2))))

    // Using individual public keys to calculate the shared public key without any secret key reconstruction
    val publicKeysSum = individualPublicKeys.map(_._2).foldLeft(cs.infinityPoint){(publicKeysSum, publicKey) => publicKeysSum.add(publicKey)}

    // Verify, that shared public key is equal to the original public key
    assert(publicKeysSum.equals(cs.decodePoint(sharedPublicKeysAfterR2(0)._2)))
  }

  //--------------------------------------------------------------------------------------------------------------

//  test("dkg_speed")
//  {
//    println("--------------------------------------------------------------------------------------")
//    println("Performance test")
//    println("--------------------------------------------------------------------------------------")
//
//    val cs = new Cryptosystem
//    val crs_h = cs.basePoint.multiply(cs.getRand)
//
//    val commiteeMembersNum = 100
//
//    println("Committee members number: " + commiteeMembersNum)
//
//    val committeeMembersAttrs = (0 until commiteeMembersNum).map(new Integer(_)).map(new CommitteeMemberAttr(_, cs.basePoint.multiply(cs.getRand)))
//
//    val committeeMembers = for (id <- committeeMembersAttrs.indices) yield {
//      new CommitteeMember(cs, id, crs_h, committeeMembersAttrs)
//    }
//
//    var t0 = System.nanoTime()
//    val r1Data = for (currentId <- committeeMembersAttrs.indices) yield {
//      committeeMembers(currentId).setKeyR1()
//    }
//    var t1 = System.nanoTime()
//    println("Round 1: " + ((t1-t0).toFloat/1000000000)/commiteeMembersNum + " sec per committee member")
//
//    t0 = System.nanoTime()
//    val r2Data = for (currentId <- committeeMembersAttrs.indices) yield {
//      committeeMembers(currentId).setKeyR2(r1Data)
//    }
//    t1 = System.nanoTime()
//    println("Round 2: " + ((t1-t0).toFloat/1000000000)/commiteeMembersNum + " sec per committee member")
//
//    t0 = System.nanoTime()
//    val r3Data = for (currentId <- committeeMembersAttrs.indices) yield {
//      committeeMembers(currentId).setKeyR3(r2Data)
//    }
//    t1 = System.nanoTime()
//    println("Round 3: " + ((t1-t0).toFloat/1000000000)/commiteeMembersNum + " sec per committee member")
//
//    t0 = System.nanoTime()
//    val r4Data = for (currentId <- committeeMembersAttrs.indices) yield {
//      committeeMembers(currentId).setKeyR4(r3Data)
//    }
//    t1 = System.nanoTime()
//    println("Round 4: " + ((t1-t0).toFloat/1000000000)/commiteeMembersNum + " sec per committee member")
//
//    t0 = System.nanoTime()
//    val r5_1Data = for (currentId <- committeeMembersAttrs.indices) yield {
//      committeeMembers(currentId).setKeyR5_1(r4Data)
//    }
//    t1 = System.nanoTime()
//    println("Round 5.1: " + ((t1-t0).toFloat/1000000000)/commiteeMembersNum + " sec per committee member")
//
//    t0 = System.nanoTime()
//    val sharedPublicKeys = for (currentId <- committeeMembersAttrs.indices) yield {
//      (currentId, committeeMembers(currentId).setKeyR5_2(r5_1Data))
//    }
//    t1 = System.nanoTime()
//    println("Round 5.2: " + ((t1-t0).toFloat/1000000000)/commiteeMembersNum + " sec per committee member")
//    println("--------------------------------------------------------------------------------------")
//  }
}
