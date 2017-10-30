package treasury.crypto
import java.security.Security
import java.math.BigInteger

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.scalatest.FunSuite
import treasury.crypto.DKGEC_Data._
import java.util.Random

class DKGECTest  extends FunSuite {

  test("dkg_functionality"){

    Security.addProvider(new BouncyCastleProvider())
    val ecSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
    val rand = new Random

    // CSR parameters
    val g = ecSpec.getG
    val h = g.multiply(new BigInteger("5"))

    val committeesIDs = (0 to 5).map(new Integer(_))

    val committees = for (id <- committeesIDs.indices) yield {
      new Committee(ecSpec, g.getEncoded(true), h.getEncoded(true), id, committeesIDs)
    }

    var r1Data = for (currentId <- committeesIDs.indices) yield {
      committees(currentId).setKeyR1()
    }

    // Changing commitments of some committees to get complain on them
    //
    r1Data.map
    {
      (x) =>
      {
        val E = x.E
//        if(rand.nextBoolean())
        if(x.issuerID == 0)
        {
          println(x.issuerID + " committee's commitment modified on Round 2")
          E(0) = ecSpec.getCurve.getInfinity.getEncoded(true)
        }
        R1Data(x.issuerID, E, x.S_a, x.S_b)
      }
    }

    val r2Data = for (currentId <- committeesIDs.indices) yield {
      committees(currentId).setKeyR2(r1Data)
    }

    val r3Data = for (currentId <- committeesIDs.indices) yield {
      committees(currentId).setKeyR3(r2Data)
    }

    // Changing commitments of some committees to get complain on them
    //
    r3Data.map
    {
      (x) =>
      {
        val commitments = x.commitments
//        if(rand.nextBoolean())
        if(x.issuerID == 1)
        {
          println(x.issuerID + " committee's commitment modified on Round 3")
          commitments(0) = ecSpec.getCurve.getInfinity.getEncoded(true)
        }
        R3Data(x.issuerID, commitments)
      }
    }

    val r4Data = for (currentId <- committeesIDs.indices) yield {
      committees(currentId).setKeyR4(r3Data)
    }

    val r5_1Data = for (currentId <- committeesIDs.indices) yield {
      committees(currentId).setKeyR5_1(r4Data)
    }

    val sharedPublicKeys = for (currentId <- committeesIDs.indices) yield {
      (currentId, committees(currentId).setKeyR5_2(r5_1Data))
    }

    //---------------------------------------------------------------
    // Verification of the shared public key for correctness
    //---------------------------------------------------------------

    // Calculating the individual public keys (pk_i = g^sk_i for each committee)
    var individualPublicKeys = for(i <- committees.indices) yield {
      (committees(i).ownID, g.multiply(committees(i).secretKey))
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
    assert(sharedPublicKeysAfterR2.map(_._2).forall(ecSpec.getCurve.decodePoint(_).equals(ecSpec.getCurve.decodePoint(sharedPublicKeysAfterR2(0)._2))))

    // Using individual public keys to calculate the shared public key without any secret key reconstruction
    val publicKeysSum = individualPublicKeys.map(_._2).foldLeft(ecSpec.getCurve.getInfinity){(publicKeysSum, publicKey) => publicKeysSum.add(publicKey)}

    // Verify, that shared public key is equal to the original public key
    assert(publicKeysSum.equals(ecSpec.getCurve.decodePoint(sharedPublicKeysAfterR2(0)._2)))
  }

  //--------------------------------------------------------------------------------------------------------------

  test("dkg_speed")
  {
    println("--------------------------------------------------------------------------------------")
    println("Performance test")
    println("--------------------------------------------------------------------------------------")

    Security.addProvider(new BouncyCastleProvider())
    val ecSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1")

    // CSR parameters
    val g = ecSpec.getG
    val h = g.multiply(new BigInteger("5"))

    val commiteesNum = 100

    println("Committees number: " + commiteesNum)

    val committeesIDs = (0 until commiteesNum).map(new Integer(_))

    val committees = for (id <- committeesIDs.indices) yield {
      new Committee(ecSpec, g.getEncoded(true), h.getEncoded(true), id, committeesIDs)
    }

    var t0 = System.nanoTime()
    val r1Data = for (currentId <- committeesIDs.indices) yield {
      committees(currentId).setKeyR1()
    }
    var t1 = System.nanoTime()
    println("Round 1: " + ((t1-t0).toFloat/1000000000)/commiteesNum + " sec per committee")

    t0 = System.nanoTime()
    val r2Data = for (currentId <- committeesIDs.indices) yield {
      committees(currentId).setKeyR2(r1Data)
    }
    t1 = System.nanoTime()
    println("Round 2: " + ((t1-t0).toFloat/1000000000)/commiteesNum + " sec per committee")

    t0 = System.nanoTime()
    val r3Data = for (currentId <- committeesIDs.indices) yield {
      committees(currentId).setKeyR3(r2Data)
    }
    t1 = System.nanoTime()
    println("Round 3: " + ((t1-t0).toFloat/1000000000)/commiteesNum + " sec per committee")

    t0 = System.nanoTime()
    val r4Data = for (currentId <- committeesIDs.indices) yield {
      committees(currentId).setKeyR4(r3Data)
    }
    t1 = System.nanoTime()
    println("Round 4: " + ((t1-t0).toFloat/1000000000)/commiteesNum + " sec per committee")

    t0 = System.nanoTime()
    val r5_1Data = for (currentId <- committeesIDs.indices) yield {
      committees(currentId).setKeyR5_1(r4Data)
    }
    t1 = System.nanoTime()
    println("Round 5.1: " + ((t1-t0).toFloat/1000000000)/commiteesNum + " sec per committee")

    t0 = System.nanoTime()
    val sharedPublicKeys = for (currentId <- committeesIDs.indices) yield {
      (currentId, committees(currentId).setKeyR5_2(r5_1Data))
    }
    t1 = System.nanoTime()
    println("Round 5.2: " + ((t1-t0).toFloat/1000000000)/commiteesNum + " sec per committee")
    println("--------------------------------------------------------------------------------------")
  }
}
