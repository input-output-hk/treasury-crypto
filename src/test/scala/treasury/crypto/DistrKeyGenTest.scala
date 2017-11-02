package treasury.crypto

import org.scalatest.FunSuite
import treasury.crypto.keygen._

class DistrKeyGenTest  extends FunSuite {

  test("dkg_interpolation"){

    val cs = new Cryptosystem
    val crs_h = cs.basePoint.multiply(cs.getRand)
    val dkg = new DistrKeyGen(cs, 0, crs_h, new Array[CommitteeMemberAttr](0))

    for(degree <- 2 to 100)
    {
      val result = dkg.testInterpolation(degree)

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

//    val committeeMembersAttrs = (0 to 5).map(new Integer(_)).map(CommitteeMemberAttr(_, cs.basePoint.multiply(cs.getRand)))
    val committeeMembersAttrs = (0 to 5).map(new Integer(_)).map(CommitteeMemberAttr(_, new Array[Byte](0)))

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
        if(x.issuerID == 1 || x.issuerID == 3)
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

    val r5_2Data = for (currentId <- committeeMembersAttrs.indices) yield {
      (currentId, committeeMembers(currentId).setKeyR5_2(r5_1Data))
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
