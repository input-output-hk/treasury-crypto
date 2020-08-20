package io.iohk.protocol.keygen

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.primitives.dlog.GroupElement
import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.keygen.datastructures.round3.R3Data
import io.iohk.protocol.keygen.math.LagrangeInterpolation
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}
import org.scalatest.FunSuite

import scala.collection.mutable.ArrayBuffer
import scala.util.{Failure, Success, Try}

class DistrKeyGenTest  extends FunSuite {

  val crs = CryptoContext.generateRandomCRS
  val ctx = new CryptoContext(Option(crs))
  import ctx.{group, hash}

  test("dkg_interpolation") {

    val ctx = new CryptoContext(None)

    for(degree <- 2 to 10) {
      assert(LagrangeInterpolation.testInterpolation(ctx, degree))
    }
  }

  //--------------------------------------------------------------------------------------------------------------

  test("dkg_functionality") {
    val keyPairs = for(id <- 1 to 10) yield encryption.createKeyPair.get
    val committeeMembersPubKeys = keyPairs.map(_._2)

    val committeeMembers = for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(ctx, keyPairs(i), committeeMembersPubKeys)
    }

    val memberIdentifier = new CommitteeIdentifier(committeeMembersPubKeys)
    val roundsData = RoundsData()

    val r1Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).doDKGRound1().get
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
          E(0) = group.groupIdentity.bytes
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
      committeeMembers(i).doDKGRound2(r1Data).get
    }

    r2Data.foreach{
      r2 =>
        DistrKeyGen.checkR2Data(ctx, r2, memberIdentifier, committeeMembersPubKeys, r1Data) match {
          case Success(_) =>
          case _ => println(s"Incorrect R2 data from member ${r2.issuerID}")
        }
    }

    roundsData.r2Data = r2Data

    val r3Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).doDKGRound3(r2Data).get
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
          commitments(0) = group.groupIdentity.bytes
        }
        R3Data(x.issuerID, commitments)
      }
    }

    r3Data.foreach{
      r3 =>
        DistrKeyGen.checkR3Data(ctx, r3, memberIdentifier, committeeMembersPubKeys, r1Data, r2Data) match {
          case Success(_) =>
          case _ => println(s"Incorrect R3 data from member ${r3.issuerID}")
        }
    }

    roundsData.r3Data = r3Data

    val r4Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).doDKGRound4(r3Data).get
    }

    r4Data.foreach{
      r4 =>
        DistrKeyGen.checkR4Data(ctx, r4, memberIdentifier, committeeMembersPubKeys, r1Data, r2Data, r3Data) match {
          case Success(_) =>
          case _ => println(s"Incorrect R4 data from member ${r4.issuerID}")
        }
    }

    roundsData.r4Data = r4Data

    val r5_1Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).doDKGRound5_1(r4Data).get
    }

    r5_1Data.foreach{
      r5 =>
        DistrKeyGen.checkR5Data(ctx, r5, memberIdentifier, committeeMembersPubKeys, r1Data, r2Data, r3Data, r4Data) match {
          case Success(_) =>
          case _ => println(s"Incorrect R5_1 data from member ${r5.issuerID}")
        }
    }

    roundsData.r5_1Data = r5_1Data

    val r5_2Data = for (i <- committeeMembersPubKeys.indices) yield {
      (committeeMembers(i).ownId, committeeMembers(i).doDKGRound5_2(r5_1Data).get)
    }

    //---------------------------------------------------------------
    // Verification of the shared public key for correctness
    //---------------------------------------------------------------

    // Calculating the individual public keys (pk_i = g^sk_i for each committee)
    var individualPublicKeys = for(i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, group.groupGenerator.pow(committeeMembers(i).secretKey).get)
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

    val sharedPublicKeys = sharedPublicKeysAfterR2.map(_._2.sharedPublicKey).map(group.reconstructGroupElement(_).get)

    // Verify, that each committee has obtained the same shared public key after round 2
    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys(0))))

    // Using individual public keys to calculate the shared public key without any secret key reconstruction
    val publicKeysSum = individualPublicKeys.map(_._2).foldLeft(group.groupIdentity){(publicKeysSum, publicKey) => publicKeysSum.multiply(publicKey).get}

    // Verify, that shared public key is equal to the original public key
    assert(publicKeysSum.equals(sharedPublicKeys(0)))

    val sharedPubKey = DistrKeyGen.getSharedPublicKey(ctx, committeeMembersPubKeys, memberIdentifier, roundsData).flatMap {
      group.reconstructGroupElement(_)
    }.get
    assert(publicKeysSum.equals(sharedPubKey))
  }

  //--------------------------------------------------------------------------------------------------------------

  test("dkg_absentees") {

    val keyPairs = for(id <- 1 to 10) yield encryption.createKeyPair.get
    val committeeMembersPubKeys = keyPairs.map(_._2)

    val committeeMembers = (for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(ctx, keyPairs(i), committeeMembersPubKeys)
    }).toBuffer

    val roundsData = RoundsData()

    val absenteesPublicKeys = ArrayBuffer[(Int, GroupElement)]()
    val absenteeIndex = 0

    committeeMembers.remove(absenteeIndex)

    val r1Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).doDKGRound1().get
    }

    roundsData.r1Data = r1Data

    absenteesPublicKeys += Tuple2(committeeMembers(absenteeIndex).ownId, group.groupGenerator.pow(committeeMembers(absenteeIndex).secretKey).get)
    committeeMembers.remove(absenteeIndex)

    val r2Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).doDKGRound2(r1Data).get
    }

    roundsData.r2Data = r2Data

    absenteesPublicKeys += Tuple2(committeeMembers(absenteeIndex).ownId, group.groupGenerator.pow(committeeMembers(absenteeIndex).secretKey).get)
    committeeMembers.remove(absenteeIndex)

    val r3Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).doDKGRound3(r2Data).get
    }

    absenteesPublicKeys += Tuple2(committeeMembers(absenteeIndex).ownId, group.groupGenerator.pow(committeeMembers(absenteeIndex).secretKey).get)
    committeeMembers.remove(absenteeIndex)

    // change commitment of the member with id = 0
    r3Data(0).commitments(0) = group.groupIdentity.bytes

    roundsData.r3Data = r3Data

    val r4Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).doDKGRound4(r3Data).get
    }

    roundsData.r4Data = r4Data

    absenteesPublicKeys += Tuple2(committeeMembers(absenteeIndex).ownId, group.groupGenerator.pow(committeeMembers(absenteeIndex).secretKey).get)
    committeeMembers.remove(absenteeIndex)

    val r5_1Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).doDKGRound5_1(r4Data).get
    }

    roundsData.r5_1Data = r5_1Data

    val r5_2Data = for (i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, committeeMembers(i).doDKGRound5_2(r5_1Data).get)
    }

    //--------------------------------------------------------------------------------
    val sharedPublicKeys = r5_2Data.map(_._2.sharedPublicKey).map(group.reconstructGroupElement(_).get)

    var individualPublicKeys = (for(i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, group.groupGenerator.pow(committeeMembers(i).secretKey).get)
    }).toBuffer

    individualPublicKeys ++= absenteesPublicKeys

    val publicKeysSum = individualPublicKeys.map(_._2).foldLeft(group.groupIdentity){(publicKeysSum, publicKey) => publicKeysSum.multiply(publicKey).get}

    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys(0))))
    assert(publicKeysSum.equals(sharedPublicKeys(0)))

    val memberIdentifier = new CommitteeIdentifier(committeeMembersPubKeys)

    val sharedPubKey = DistrKeyGen.getSharedPublicKey(ctx, committeeMembersPubKeys, memberIdentifier, roundsData).flatMap {
      group.reconstructGroupElement(_)
    }.get
    assert(publicKeysSum.equals(sharedPubKey))
  }

  //--------------------------------------------------------------------------------------------------------------

  test("dkg_state") {

    val keyPairs = for(id <- 1 to 10) yield encryption.createKeyPair.get
    val committeeMembersPubKeys = keyPairs.map(_._2)

    val committeeMembers = (for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(ctx, keyPairs(i), committeeMembersPubKeys)
    }).toBuffer

    def reCreateMember(memberIndex: Int, roundsData: RoundsData){
      committeeMembers(memberIndex) = new CommitteeMember(ctx, keyPairs(memberIndex), committeeMembersPubKeys, roundsData)
    }
    val roundsData = RoundsData()

    val r1Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).doDKGRound1().get
    }

    val violatorIndex = committeeMembers.length - 1
    r1Data(violatorIndex).E(0) = group.groupIdentity.bytes // provoke complaints on the member
    committeeMembers.remove(violatorIndex) // remove member, as he will be ignored anyway in the further rounds

    roundsData.r1Data = r1Data
    reCreateMember(0, roundsData)

    val r2Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).doDKGRound2(r1Data).get
    }

    roundsData.r2Data = r2Data
    reCreateMember(1, roundsData)

    val r3Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).doDKGRound3(r2Data).get
    }

    // change commitment of the member with id = 0
    r3Data(0).commitments(0) = group.groupIdentity.bytes

    roundsData.r3Data = r3Data
    reCreateMember(2, roundsData)

    val r4Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).doDKGRound4(r3Data).get
    }

    roundsData.r4Data = r4Data
    reCreateMember(3, roundsData)

    val r5_1Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).doDKGRound5_1(r4Data).get
    }

    roundsData.r5_1Data = r5_1Data
    reCreateMember(4, roundsData)

    val r5_2Data = for (i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, committeeMembers(i).doDKGRound5_2(r5_1Data).get)
    }

    roundsData.r5_2Data = r5_2Data.map(_._2)
    reCreateMember(5, roundsData)

    //--------------------------------------------------------------------------------
    val memberIndex = 1

//    roundsData.r1Data.head.E(0) = Array.fill(1)(0.toByte)

    val sharedPubKey = {
      Try {
        val seed = ctx.hash.hash(keyPairs(memberIndex)._1.toByteArray ++ "DKG Seed".getBytes)
        new DistrKeyGen(ctx, keyPairs(memberIndex), committeeMembers(memberIndex).secretKey, seed, committeeMembersPubKeys, new CommitteeIdentifier(committeeMembersPubKeys), roundsData)
      } match {
        case Success(dkg) =>
          dkg.roundsDataCache.r5_2Data.headOption match {
            case Some(data) => group.reconstructGroupElement(data.sharedPublicKey).get
            case None => group.groupIdentity
          }
        case Failure(e) =>
          println("EXCEPTION: " + e.getMessage)
          group.groupIdentity
      }
    }
    //--------------------------------------------------------------------------------
    val sharedPublicKeys = r5_2Data.map(_._2.sharedPublicKey).map(group.reconstructGroupElement(_).get)

    val individualPublicKeys = (for(i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, group.groupGenerator.pow(committeeMembers(i).secretKey).get)
    }).toBuffer
    val publicKeysSum = individualPublicKeys.map(_._2).foldLeft(group.groupIdentity){(publicKeysSum, publicKey) => publicKeysSum.multiply(publicKey).get}

    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys.head)))
    assert(publicKeysSum.equals(sharedPublicKeys.head))
    assert(publicKeysSum.equals(sharedPubKey))
  }

  //--------------------------------------------------------------------------------------------------------------

  // state restoring together with presence of the protocol violators and absentees during protocol execution
  test("dkg_complex") {

    val keyPairs = for(id <- 1 to 14) yield encryption.createKeyPair.get
    val committeeMembersPubKeys = keyPairs.map(_._2)

    val committeeMembers = (for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(ctx, keyPairs(i), committeeMembersPubKeys)
    }).toBuffer

    def reCreateMember(memberIndex: Int, roundsData: RoundsData) {
      committeeMembers(memberIndex) = new CommitteeMember(ctx, keyPairs(memberIndex), committeeMembersPubKeys, roundsData)
    }

    def removeMemberFromEnd(absenteesPublicKeysAccumulator: ArrayBuffer[(Int, GroupElement)]) {
      val index = committeeMembers.length - 1
      absenteesPublicKeysAccumulator += Tuple2(committeeMembers(index).ownId, group.groupGenerator.pow(committeeMembers(index).secretKey).get)
      committeeMembers.remove(index)
    }

    val roundsData = RoundsData()
    val absenteesPublicKeys = ArrayBuffer[(Int, GroupElement)]()

    // For round 1 there is no need to save public keys of violators, as the will not be used for shared public key creation
    var violatorOfRound1Index = committeeMembers.length - 1
    committeeMembers.remove(violatorOfRound1Index) // absentee and also a violator on the 1-st round

    val r1Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).doDKGRound1().get
    }

    violatorOfRound1Index = committeeMembers.length - 1
    r1Data(violatorOfRound1Index).E(0) = group.groupIdentity.bytes // provoke complaints on the member
    committeeMembers.remove(violatorOfRound1Index) // remove member, as he will be ignored anyway in the further rounds

    roundsData.r1Data = r1Data
    reCreateMember(0, roundsData)

    removeMemberFromEnd(absenteesPublicKeys) // absentee on the 2-nd and 3-rd rounds

    val r2Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).doDKGRound2(r1Data).get
    }

    roundsData.r2Data = r2Data
    reCreateMember(1, roundsData)

    removeMemberFromEnd(absenteesPublicKeys) // absentee on the 3-rd round

    val r3Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).doDKGRound3(r2Data).get
    }

    // change commitment of the member, which will not participate in rounds  5_1, 5_2
    r3Data(committeeMembers.length - 2).commitments(0) = group.groupIdentity.bytes // protocol violator on the 3-rd round

    roundsData.r3Data = r3Data
    reCreateMember(2, roundsData)

    removeMemberFromEnd(absenteesPublicKeys) // just member who will not participate in commitments verification and will not post the violators and absentees secret shares (in round 5_1)

    val r4Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).doDKGRound4(r3Data).get
    }

    roundsData.r4Data = r4Data
    reCreateMember(3, roundsData)

    removeMemberFromEnd(absenteesPublicKeys) // just the member who will not post the violators and absentees secret shares

    val r5_1Data = for (i <- committeeMembers.indices) yield {
      committeeMembers(i).doDKGRound5_1(r4Data).get
    }

    roundsData.r5_1Data = r5_1Data
    reCreateMember(4, roundsData)

    removeMemberFromEnd(absenteesPublicKeys) // just the member who will not reconstruct the violators and absentees secrets and obtain a shared public key

    val r5_2Data = for (i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, committeeMembers(i).doDKGRound5_2(r5_1Data).get)
    }

    roundsData.r5_2Data = r5_2Data.map(_._2)
    reCreateMember(5, roundsData)

    //--------------------------------------------------------------------------------

    val memberIndex = 6

//    roundsData.r1Data.head.E(0) = Array.fill(1)(0.toByte)

    val sharedPubKey = {
      Try {
        val seed = ctx.hash.hash(keyPairs(memberIndex)._1.toByteArray ++ "DKG Seed".getBytes)
        new DistrKeyGen(ctx, keyPairs(memberIndex), committeeMembers(memberIndex).secretKey, seed, committeeMembersPubKeys, new CommitteeIdentifier(committeeMembersPubKeys), roundsData)
      } match {
        case Success(dkg) =>
          dkg.roundsDataCache.r5_2Data.headOption match {
            case Some(data) => group.reconstructGroupElement(data.sharedPublicKey).get
            case None => group.groupIdentity
          }
        case Failure(e) =>
          println("EXCEPTION: " + e.getMessage)
          group.groupIdentity
      }
    }
    //--------------------------------------------------------------------------------
    val sharedPublicKeys = r5_2Data.map(_._2.sharedPublicKey).map(group.reconstructGroupElement(_).get)

    var individualPublicKeys = (for(i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, group.groupGenerator.pow(committeeMembers(i).secretKey).get)
    }).toBuffer

    individualPublicKeys ++= absenteesPublicKeys

    val publicKeysSum = individualPublicKeys.map(_._2).foldLeft(group.groupIdentity){(publicKeysSum, publicKey) => publicKeysSum.multiply(publicKey).get}

    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys(0))))
    assert(publicKeysSum.equals(sharedPublicKeys(0)))
    assert(publicKeysSum.equals(sharedPubKey))

    val memberIdentifier = new CommitteeIdentifier(committeeMembersPubKeys)

    val sharedPubKeyIndependent = DistrKeyGen.getSharedPublicKey(ctx, committeeMembersPubKeys, memberIdentifier, roundsData).flatMap {
      group.reconstructGroupElement(_)
    }.get
    assert(publicKeysSum.equals(sharedPubKeyIndependent))
  }

  test("generateRecoveryKeyShare") {

    val keyPairs = for(id <- 1 to 2) yield encryption.createKeyPair.get
    val committeeMembersPubKeys = keyPairs.map(_._2)

    val committeeMembers = for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(ctx, keyPairs(i), committeeMembersPubKeys)
    }

    val r1Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).doDKGRound1().get
    }

    val openedShare = DistrKeyGen.generateRecoveryKeyShare(ctx, committeeMembers(0).memberIdentifier, keyPairs(0), keyPairs(1)._2, r1Data).get
    val verified = DistrKeyGen.validateRecoveryKeyShare(ctx, committeeMembers(0).memberIdentifier, keyPairs(0)._2, keyPairs(1)._2, r1Data, openedShare).isSuccess

    assert(verified)
  }

  test("recoverPrivateKeyByOpenedShares") {

    val transportKeyPairs = for(id <- 1 to 3) yield encryption.createKeyPair.get
    val committeeMembersPubKeys = transportKeyPairs.map(_._2)

    val committeeMembers = for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(ctx, transportKeyPairs(i), committeeMembersPubKeys)
    }

    val r1Data = for (i <- committeeMembersPubKeys.indices) yield committeeMembers(i).doDKGRound1().get
    val r2Data = for (i <- committeeMembersPubKeys.indices) yield committeeMembers(i).doDKGRound2(r1Data).get
    val r3Data = for (i <- committeeMembersPubKeys.indices) yield committeeMembers(i).doDKGRound3(r2Data).get

    val identifier = committeeMembers(0).memberIdentifier

    val violatorTransportPubKey = transportKeyPairs(2)._2
    val violatorId = identifier.getId(violatorTransportPubKey)
    val violatorPubKey = group.reconstructGroupElement(r3Data(2).commitments(0)).get

    val openedShare1 = DistrKeyGen.generateRecoveryKeyShare(ctx, identifier, transportKeyPairs(0), violatorTransportPubKey, r1Data).get
    val openedShare2 = DistrKeyGen.generateRecoveryKeyShare(ctx, identifier, transportKeyPairs(1), violatorTransportPubKey, r1Data).get

    val recoveredPrivKey = DistrKeyGen.recoverPrivateKeyByOpenedShares(ctx, committeeMembers.size, Seq(openedShare1, openedShare2), Some(violatorPubKey))
    assert(recoveredPrivKey.isSuccess)
  }
}
