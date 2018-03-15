package treasury.crypto

import org.scalatest.FunSuite
import treasury.crypto.core.{CommitteeIdentifier, Cryptosystem}
import treasury.crypto.keygen._
import treasury.crypto.keygen.datastructures.round1.R1Data
import treasury.crypto.keygen.datastructures.round3.R3Data

import scala.collection.mutable.ArrayBuffer
import scala.util.{Failure, Success}

class DistrKeyGenTest  extends FunSuite {

  test("dkg_interpolation") {

    val cs = new Cryptosystem

    for(degree <- 2 to 10) {
      assert(LagrangeInterpolation.testInterpolation(cs, degree))
    }
  }

  //--------------------------------------------------------------------------------------------------------------

  test("dkg_functionality") {

    val cs = new Cryptosystem
    val crs_h = cs.basePoint.multiply(cs.getRand)

    val keyPairs = for(id <- 1 to 10) yield cs.createKeyPair
    val committeeMembersPubKeys = keyPairs.map(_._2)

    val committeeMembers = for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(cs, crs_h, keyPairs(i), committeeMembersPubKeys)
    }

    val memberIdentifier = new CommitteeIdentifier(committeeMembersPubKeys)
    val roundsData = RoundsData()

    val r1Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR1()
    }

    // Changing commitments of some committee members to get complain on them
    //
    r1Data.map {
      (x) => {
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

    r1Data.foreach{
      r1 =>
        DistrKeyGen.checkR1Data(r1, memberIdentifier, committeeMembersPubKeys) match {
          case Success(_) =>
          case _ => println(s"Incorrect R1 data from member ${r1.issuerID}")
        }
    }

    roundsData.r1Data = r1Data

    val r2Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR2(r1Data)
    }

    r2Data.foreach{
      r2 =>
        DistrKeyGen.checkR2Data(r2, memberIdentifier, committeeMembersPubKeys, cs) match {
          case Success(_) =>
          case _ => println(s"Incorrect R2 data from member ${r2.issuerID}")
        }
    }

    roundsData.r2Data = r2Data

    val r3Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR3(r2Data)
    }

    // Changing commitments of some committee members to get complain on them
    //
    r3Data.map {
      (x) => {
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

    r3Data.foreach{
      r3 =>
        DistrKeyGen.checkR3Data(r3, memberIdentifier, committeeMembersPubKeys) match {
          case Success(_) =>
          case _ => println(s"Incorrect R3 data from member ${r3.issuerID}")
        }
    }

    roundsData.r3Data = r3Data

    val r4Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR4(r3Data)
    }

    r4Data.foreach{
      r4 =>
        DistrKeyGen.checkR4Data(r4, memberIdentifier, committeeMembersPubKeys, cs, crs_h, r1Data, r3Data) match {
          case Success(_) =>
          case _ => println(s"Incorrect R4 data from member ${r4.issuerID}")
        }
    }

    roundsData.r4Data = r4Data

    val r5_1Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR5_1(r4Data)
    }

    r5_1Data.foreach{
      r5 =>
        DistrKeyGen.checkR5Data(r5, memberIdentifier, committeeMembersPubKeys, cs, r1Data) match {
          case Success(_) =>
          case _ => println(s"Incorrect R5_1 data from member ${r5.issuerID}")
        }
    }

    roundsData.r5_1Data = r5_1Data

    val r5_2Data = for (i <- committeeMembersPubKeys.indices) yield {
      (committeeMembers(i).ownId, committeeMembers(i).setKeyR5_2(r5_1Data))
    }

    //---------------------------------------------------------------
    // Verification of the shared public key for correctness
    //---------------------------------------------------------------

    // Calculating the individual public keys (pk_i = g^sk_i for each committee)
    var individualPublicKeys = for(i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, cs.basePoint.multiply(committeeMembers(i).secretKey))
    }

    var sharedPublicKeysAfterR2 = r5_2Data

    // Violators detected on the 2-nd round doesn't participate in the shared public key generation at all
    for(i <- r2Data.indices) {
      for(j <- r2Data(i).complaints.indices) {
        val violatorID = r2Data(i).complaints(j).violatorID

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

    val sharedPubKey = cs.decodePoint(DistrKeyGen.getSharedPublicKey(cs, committeeMembersPubKeys, memberIdentifier, roundsData).get)
    assert(publicKeysSum.equals(sharedPubKey))
  }

  //--------------------------------------------------------------------------------------------------------------

  test("dkg_absentees") {

    val cs = new Cryptosystem
    val crs_h = cs.basePoint.multiply(cs.getRand)

    val keyPairs = for(id <- 1 to 10) yield cs.createKeyPair
    val committeeMembersPubKeys = keyPairs.map(_._2)

    val committeeMembers = (for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(cs, crs_h, keyPairs(i), committeeMembersPubKeys)
    }).toBuffer

    val roundsData = RoundsData()

    val absenteesPublicKeys = ArrayBuffer[(Integer, org.bouncycastle.math.ec.ECPoint)]()
    val absenteeIndex = 0

    committeeMembers.remove(absenteeIndex)

    val r1Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).setKeyR1()
    }

    roundsData.r1Data = r1Data

    absenteesPublicKeys += Tuple2(committeeMembers(absenteeIndex).ownId, cs.basePoint.multiply(committeeMembers(absenteeIndex).secretKey))
    committeeMembers.remove(absenteeIndex)

    val r2Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).setKeyR2(r1Data)
    }

    roundsData.r2Data = r2Data

    absenteesPublicKeys += Tuple2(committeeMembers(absenteeIndex).ownId, cs.basePoint.multiply(committeeMembers(absenteeIndex).secretKey))
    committeeMembers.remove(absenteeIndex)

    val r3Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).setKeyR3(r2Data)
    }

    absenteesPublicKeys += Tuple2(committeeMembers(absenteeIndex).ownId, cs.basePoint.multiply(committeeMembers(absenteeIndex).secretKey))
    committeeMembers.remove(absenteeIndex)

    // change commitment of the member with id = 0
    r3Data(0).commitments(0) = cs.infinityPoint.getEncoded(true)

    roundsData.r3Data = r3Data

    val r4Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).setKeyR4(r3Data)
    }

    roundsData.r4Data = r4Data

    absenteesPublicKeys += Tuple2(committeeMembers(absenteeIndex).ownId, cs.basePoint.multiply(committeeMembers(absenteeIndex).secretKey))
    committeeMembers.remove(absenteeIndex)

    val r5_1Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).setKeyR5_1(r4Data)
    }

    roundsData.r5_1Data = r5_1Data

    val r5_2Data = for (i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, committeeMembers(i).setKeyR5_2(r5_1Data))
    }

    //--------------------------------------------------------------------------------
    val sharedPublicKeys = r5_2Data.map(_._2.sharedPublicKey).map(x => cs.decodePoint(x).normalize())

    var individualPublicKeys = (for(i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, cs.basePoint.multiply(committeeMembers(i).secretKey))
    }).toBuffer

    individualPublicKeys ++= absenteesPublicKeys

    val publicKeysSum = individualPublicKeys.map(_._2).foldLeft(cs.infinityPoint){(publicKeysSum, publicKey) => publicKeysSum.add(publicKey)}.normalize()

    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys(0))))
    assert(publicKeysSum.equals(sharedPublicKeys(0)))

    val memberIdentifier = new CommitteeIdentifier(committeeMembersPubKeys)

    val sharedPubKey = cs.decodePoint(DistrKeyGen.getSharedPublicKey(cs, committeeMembersPubKeys, memberIdentifier, roundsData).get)
    assert(publicKeysSum.equals(sharedPubKey))
  }

  //--------------------------------------------------------------------------------------------------------------

  test("dkg_state") {

    val cs = new Cryptosystem
    val crs_h = cs.basePoint.multiply(cs.getRand)

    val keyPairs = for(id <- 1 to 10) yield cs.createKeyPair
    val committeeMembersPubKeys = keyPairs.map(_._2)

    val committeeMembers = (for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(cs, crs_h, keyPairs(i), committeeMembersPubKeys)
    }).toBuffer

    def reCreateMember(memberIndex: Int, roundsData: RoundsData){
      committeeMembers(memberIndex) = new CommitteeMember(cs, crs_h, keyPairs(memberIndex), committeeMembersPubKeys)
      committeeMembers(memberIndex).setState(roundsData)
    }
    val roundsData = RoundsData()

    val r1Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).setKeyR1()
    }

    val violatorIndex = committeeMembers.length - 1
    r1Data(violatorIndex).E(0) = cs.infinityPoint.getEncoded(true) // provoke complaints on the member
    committeeMembers.remove(violatorIndex) // remove member, as he will be ignored anyway in the further rounds

    roundsData.r1Data = r1Data
    reCreateMember(0, roundsData)

    val r2Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).setKeyR2(r1Data)
    }

    roundsData.r2Data = r2Data
    reCreateMember(1, roundsData)

    val r3Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).setKeyR3(r2Data)
    }

    // change commitment of the member with id = 0
    r3Data(0).commitments(0) = cs.infinityPoint.getEncoded(true)

    roundsData.r3Data = r3Data
    reCreateMember(2, roundsData)

    val r4Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).setKeyR4(r3Data)
    }

    roundsData.r4Data = r4Data
    reCreateMember(3, roundsData)

    val r5_1Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).setKeyR5_1(r4Data)
    }

    roundsData.r5_1Data = r5_1Data
    reCreateMember(4, roundsData)

    val r5_2Data = for (i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, committeeMembers(i).setKeyR5_2(r5_1Data))
    }

    roundsData.r5_2Data = r5_2Data.map(_._2)
    reCreateMember(5, roundsData)

    //--------------------------------------------------------------------------------
    val memberIndex = 1
    val dkg = new DistrKeyGen(cs, crs_h, keyPairs(memberIndex), committeeMembersPubKeys, new CommitteeIdentifier(committeeMembersPubKeys))

    //    roundsData.r1Data.head.E(0) = Array.fill(1)(0.toByte)

    val sharedPubKey = dkg.setState(committeeMembers(memberIndex).secretKey.toByteArray, roundsData) match {
      case Success(sharedPubKeyOpt) =>
        sharedPubKeyOpt match {
          case Some(key) => cs.decodePoint(key).normalize()
          case None => cs.infinityPoint
        }
      case Failure(e) => println("EXCEPTION: " + e.getMessage)
    }
    //--------------------------------------------------------------------------------
    val sharedPublicKeys = r5_2Data.map(_._2.sharedPublicKey).map(x => cs.decodePoint(x).normalize())

    val individualPublicKeys = (for(i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, cs.basePoint.multiply(committeeMembers(i).secretKey))
    }).toBuffer
    val publicKeysSum = individualPublicKeys.map(_._2).foldLeft(cs.infinityPoint){(publicKeysSum, publicKey) => publicKeysSum.add(publicKey)}.normalize()

    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys.head)))
    assert(publicKeysSum.equals(sharedPublicKeys.head))
    assert(publicKeysSum.equals(sharedPubKey))
  }

  //--------------------------------------------------------------------------------------------------------------

  // state restoring together with presence of the protocol violators and absentees during protocol execution
  test("dkg_complex") {

    val cs = new Cryptosystem
    val crs_h = cs.basePoint.multiply(cs.getRand)

    val keyPairs = for(id <- 1 to 14) yield cs.createKeyPair
    val committeeMembersPubKeys = keyPairs.map(_._2)

    val committeeMembers = (for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(cs, crs_h, keyPairs(i), committeeMembersPubKeys)
    }).toBuffer

    def reCreateMember(memberIndex: Int, roundsData: RoundsData) {
      committeeMembers(memberIndex) = new CommitteeMember(cs, crs_h, keyPairs(memberIndex), committeeMembersPubKeys)
      committeeMembers(memberIndex).setState(roundsData)
    }

    def removeMemberFromEnd(absenteesPublicKeysAccumulator: ArrayBuffer[(Integer, org.bouncycastle.math.ec.ECPoint)]) {
      val index = committeeMembers.length - 1
      absenteesPublicKeysAccumulator += Tuple2(committeeMembers(index).ownId, cs.basePoint.multiply(committeeMembers(index).secretKey))
      committeeMembers.remove(index)
    }

    val roundsData = RoundsData()
    val absenteesPublicKeys = ArrayBuffer[(Integer, org.bouncycastle.math.ec.ECPoint)]()

    // For round 1 there is no need to save public keys of violators, as the will not be used for shared public key creation
    var violatorOfRound1Index = committeeMembers.length - 1
    committeeMembers.remove(violatorOfRound1Index) // absentee and also a violator on the 1-st round

    val r1Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).setKeyR1()
    }

    violatorOfRound1Index = committeeMembers.length - 1
    r1Data(violatorOfRound1Index).E(0) = cs.infinityPoint.getEncoded(true) // provoke complaints on the member
    committeeMembers.remove(violatorOfRound1Index) // remove member, as he will be ignored anyway in the further rounds

    roundsData.r1Data = r1Data
    reCreateMember(0, roundsData)

    removeMemberFromEnd(absenteesPublicKeys) // absentee on the 2-nd and 3-rd rounds

    val r2Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).setKeyR2(r1Data)
    }

    roundsData.r2Data = r2Data
    reCreateMember(1, roundsData)

    removeMemberFromEnd(absenteesPublicKeys) // absentee on the 3-rd round

    val r3Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).setKeyR3(r2Data)
    }

    // change commitment of the member, which will not participate in rounds  5_1, 5_2
    r3Data(committeeMembers.length - 2).commitments(0) = cs.infinityPoint.getEncoded(true) // protocol violator on the 3-rd round

    roundsData.r3Data = r3Data
    reCreateMember(2, roundsData)

    removeMemberFromEnd(absenteesPublicKeys) // just member who will not participate in commitments verification and will not post the violators and absentees secret shares (in round 5_1)

    val r4Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).setKeyR4(r3Data)
    }

    roundsData.r4Data = r4Data
    reCreateMember(3, roundsData)

    removeMemberFromEnd(absenteesPublicKeys) // just the member who will not post the violators and absentees secret shares

    val r5_1Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).setKeyR5_1(r4Data)
    }

    roundsData.r5_1Data = r5_1Data
    reCreateMember(4, roundsData)

    removeMemberFromEnd(absenteesPublicKeys) // just the member who will not reconstruct the violators and absentees secrets and obtain a shared public key

    val r5_2Data = for (i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, committeeMembers(i).setKeyR5_2(r5_1Data))
    }

    roundsData.r5_2Data = r5_2Data.map(_._2)
    reCreateMember(5, roundsData)

    //--------------------------------------------------------------------------------

    val memberIndex = 6
    val dkg = new DistrKeyGen(cs, crs_h, keyPairs(memberIndex), committeeMembersPubKeys, new CommitteeIdentifier(committeeMembersPubKeys))

//    roundsData.r1Data.head.E(0) = Array.fill(1)(0.toByte)

    val sharedPubKey = dkg.setState(committeeMembers(memberIndex).secretKey.toByteArray, roundsData) match {
      case Success(sharedPubKeyOpt) =>
        sharedPubKeyOpt match {
          case Some(key) => cs.decodePoint(key).normalize()
          case None => cs.infinityPoint
      }
      case Failure(e) => println("EXCEPTION: " + e.getMessage)
    }
    //--------------------------------------------------------------------------------
    val sharedPublicKeys = r5_2Data.map(_._2.sharedPublicKey).map(x => cs.decodePoint(x).normalize())

    var individualPublicKeys = (for(i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, cs.basePoint.multiply(committeeMembers(i).secretKey))
    }).toBuffer

    individualPublicKeys ++= absenteesPublicKeys

    val publicKeysSum = individualPublicKeys.map(_._2).foldLeft(cs.infinityPoint){(publicKeysSum, publicKey) => publicKeysSum.add(publicKey)}.normalize()

    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys(0))))
    assert(publicKeysSum.equals(sharedPublicKeys(0)))
    assert(publicKeysSum.equals(sharedPubKey))

    val memberIdentifier = new CommitteeIdentifier(committeeMembersPubKeys)

    val sharedPubKeyIndependent = cs.decodePoint(DistrKeyGen.getSharedPublicKey(cs, committeeMembersPubKeys, memberIdentifier, roundsData).get)
    assert(publicKeysSum.equals(sharedPubKeyIndependent))
  }
}
