package treasury.crypto

import org.scalatest.FunSuite
import treasury.crypto.core.Cryptosystem
import treasury.crypto.keygen._

class DistrKeyGenTest  extends FunSuite {

  test("dkg_interpolation"){

    val cs = new Cryptosystem

    for(degree <- 2 to 10)
    {
      val result = LagrangeInterpolation.testInterpolation(cs, degree)

      assert(result)

      print("degree " + degree + " : ")
      if (result)
        println("OK")
      else
        println("ERR")
    }
  }

  //--------------------------------------------------------------------------------------------------------------

  test("dkg_functionality"){

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

    val r1Data = for (i <- committeeMembersAttrs.indices) yield {
      committeeMembers(i).setKeyR1()
    }

    // Changing commitments of some committee members to get complain on them
    //
    r1Data.map
    {
      (x) =>
      {
        val E = x.E
//        if(rand.nextBoolean())
        if(x.issuerID == 1)
        {
          println(x.issuerID + " committee members's commitment modified on Round 2")
          E(0) = cs.infinityPoint.getEncoded(true)
        }
        R1Data(x.issuerID, E, x.S_a, x.S_b)
      }
    }

    val r2Data = for (i <- committeeMembersAttrs.indices) yield {
      committeeMembers(i).setKeyR2(r1Data)
    }

    val r3Data = for (i <- committeeMembersAttrs.indices) yield {
      committeeMembers(i).setKeyR3(r2Data)
    }

    // Changing commitments of some committee members to get complain on them
    //
    r3Data.map
    {
      (x) =>
      {
        val commitments = x.commitments
//        if(rand.nextBoolean())
        if(x.issuerID == 2 || x.issuerID == 3)
        {
          println(x.issuerID + " committee members's commitment modified on Round 3")
          commitments(0) = cs.infinityPoint.getEncoded(true)
        }
        R3Data(x.issuerID, commitments)
      }
    }

    val r4Data = for (i <- committeeMembersAttrs.indices) yield {
      committeeMembers(i).setKeyR4(r3Data)
    }

    val r5_1Data = for (i <- committeeMembersAttrs.indices) yield {
      committeeMembers(i).setKeyR5_1(r4Data)
    }

    val r5_2Data = for (i <- committeeMembersAttrs.indices) yield {
      (committeeMembers(i).ownID, committeeMembers(i).setKeyR5_2(r5_1Data))
    }

    //---------------------------------------------------------------
    // Verification of the shared public key for correctness
    //---------------------------------------------------------------

    // Calculating the individual public keys (pk_i = g^sk_i for each committee)
    var individualPublicKeys = for(i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownID, cs.basePoint.multiply(committeeMembers(i).secretKey))
    }

    var sharedPublicKeysAfterR2 = r5_2Data

    // Violators detected on the 2-nd round doesn't participate in the shared public key generation at all
    for(i <- r2Data.indices)
    {
      for(j <- r2Data(i).complains.indices)
      {
        val violatorID = r2Data(i).complains(j).violatorID

        individualPublicKeys = individualPublicKeys.filter(_._1 != violatorID)
        sharedPublicKeysAfterR2 = sharedPublicKeysAfterR2.filter(_._1 != violatorID)
      }
    }

    val sharedPublicKeys = sharedPublicKeysAfterR2.map(_._2.sharedPublicKey).map(cs.decodePoint)

    // Verify, that each committee has obtained the same shared public key after round 2
    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys(0))))

    // Using individual public keys to calculate the shared public key without any secret key reconstruction
    val publicKeysSum = individualPublicKeys.map(_._2).foldLeft(cs.infinityPoint){(publicKeysSum, publicKey) => publicKeysSum.add(publicKey)}

    // Verify, that shared public key is equal to the original public key
    assert(publicKeysSum.equals(sharedPublicKeys(0)))
  }
}
