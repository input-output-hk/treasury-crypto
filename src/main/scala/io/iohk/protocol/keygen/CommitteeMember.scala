package io.iohk.protocol.keygen

import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.protocol.CommitteeIdentifier
import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.keygen.datastructures.round2.R2Data
import io.iohk.protocol.keygen.datastructures.round3.R3Data
import io.iohk.protocol.keygen.datastructures.round4.R4Data
import io.iohk.protocol.keygen.datastructures.round5_1.R5_1Data
import io.iohk.protocol.keygen.datastructures.round5_2.R5_2Data
import io.iohk.protocol.voting.approval.ApprovalContext
import io.iohk.protocol.voting.common.Tally

import scala.util.Try

/**
  * CommitteeMember is strictly for testing purposes at this point. It is a wrapper for the functionality performed
  * by a committee member. It wraps 5-round distributed key generation and 4-round tally decryption.

  * TODO: actually it will be useful to have a wrapper like this for the production use to ease integration with the
  *       target platform. We already have a wrapper for a voter, so it will be nice to have it also for a committee member.
  *       It will simplify library API and eliminate the need for a target platform to interact separately with different
  *       components (DistKeyGen, DecryptionManager, RandomnessGenManager) like it is now in our TreasuryCoin
  *       prototype on top of Scorex.
  * TODO: consider to refactor CommitteeMember class for being a full-fledged wrapper for a committee member functionality
  *
  * @param ctx
  * @param transportKeyPair key pair of this committee member
  *                         TODO: here transportKeyPair serves also as a key pair for generating shared key.
  *                         TODO: It is ok for testing but not the case for real world.
  * @param committeeMembersPubKeys public keys of all committee members
  * @param roundsData
  */
class CommitteeMember(val ctx: ApprovalContext,
                               val transportKeyPair: KeyPair,
                               val committeeMembersPubKeys: Seq[PubKey],
                               roundsData: RoundsData = RoundsData()) {
  import ctx.cryptoContext.{group, hash}

  //type TALLY <: Tally

  val memberIdentifier = new CommitteeIdentifier(committeeMembersPubKeys)

  // TODO: transport key pair serves also as a key pair for generating shared key. Originally these pairs were designed to be different.
  val secretKey = transportKeyPair._1
  val publicKey = transportKeyPair._2

  // DistrKeyGen instance is used to run distributed key generation protocol
  val seed = hash.hash(secretKey.toByteArray ++ "DKG Seed".getBytes) // TODO: secretKey should not be used to extract seed
  protected val dkg = new DistrKeyGen(ctx.cryptoContext, transportKeyPair, secretKey, seed, committeeMembersPubKeys, memberIdentifier, roundsData)
  var dkgViolatorsKeys: Option[Map[PubKey, Option[PrivKey]]] = None

  // Tally should be initialized after DKG is finished, because it requires keys of committee members disqualified during DKG
//  protected var summator: Option[TALLY#SUMMATOR] = None
//  protected var tally: Option[TALLY] = None
//  protected var tallyResult: Option[TALLY#RESULT] = None // decrypted results of voting for each proposal (map of proposalId -> Result)

  val ownId: Int = dkg.ownID

  def doDKGRound1(): Try[R1Data] = Try {
    dkg.doRound1().get
  }

  def doDKGRound2(r1Data: Seq[R1Data]): Try[R2Data] = Try {
    dkg.doRound2(r1Data).get
  }

  def doDKGRound3(r2Data: Seq[R2Data]): Try[R3Data] = Try {
    dkg.doRound3(r2Data).get
  }

  def doDKGRound4(r3Data: Seq[R3Data]): Try[R4Data] = Try {
    dkg.doRound4(r3Data).get
  }

  def doDKGRound5_1(r4Data: Seq[R4Data]): Try[R5_1Data] = Try {
    dkg.doRound5_1(r4Data).get
  }

  def doDKGRound5_2(r5_1Data: Seq[R5_1Data]): Try[R5_2Data] = Try {

    val data = dkg.doRound5_2(r5_1Data).get

    var violatorKeys: Map[PubKey, Option[PrivKey]] = dkg.getAllDisqualifiedIds.map(memberIdentifier.getPubKey(_).get -> None).toMap
    data.violatorsSecretKeys.foreach{ sk =>
      val violatorPubKey = memberIdentifier.getPubKey(sk.ownerID).get
      val violatorPrivKey = BigInt(sk.secretKey)
      assert(violatorPubKey == group.groupGenerator.pow(violatorPrivKey).get)
      violatorKeys += violatorPubKey -> Some(violatorPrivKey)
    }

    dkgViolatorsKeys = Some(violatorKeys)

    data
  }

//  def initTally: TALLY
//
//  /* Tally stage. It should be started only when all rounds of DKG are executed. */
//
//  def doTallyR1(s: TALLY#SUMMATOR): Try[TALLY#R1DATA] = Try {
//    summator = Some(s)
//    tally = Some(initTally)
//    tally.get.generateR1Data(s, (secretKey, publicKey)).get
//  }
//
//  def doTallyR2(tallyR1DataAll: Seq[TALLY#R1DATA], dkgR1DataAll: Seq[R1Data]): Try[TALLY#R2DATA] = Try {
//    val tallyR1 = tally.get
//    val s = summator.get.asInstanceOf[tallyR1.SUMMATOR]
//    val r1DataAll = tallyR1DataAll.map(_.asInstanceOf[tallyR1.R1DATA])
//
//    val verifiedR1DataAll = r1DataAll.filter { r1Data =>
//      memberIdentifier.getPubKey(r1Data.issuerId).flatMap { pubKey =>
//        tallyR1.verifyRound1Data(s, pubKey, r1Data) match {
//          case true => Some(Unit)
//          case false => None
//        }
//      }.isDefined
//    }
//
//    require(tallyR1.executeRound1(s, verifiedR1DataAll).isSuccess)
//    tallyR1.generateR2Data((secretKey, publicKey), dkgR1DataAll).get
//  }
//
//  def doTallyR3(tallyR2DataAll: Seq[TALLY#R2DATA],
//                dkgR1DataAll: Seq[R1Data],
//                expertBallots: Seq[TALLY#EXPERTBALLOT]): Try[TALLY#R3DATA] = Try {
//    val tallyR2 = tally.get
//    val r2DataAll = tallyR2DataAll.map(_.asInstanceOf[tallyR2.R2DATA])
//    val ballots = expertBallots.map(_.asInstanceOf[tallyR2.EXPERTBALLOT])
//
//    val verifiedR2DataAll = r2DataAll.filter { r2Data =>
//      memberIdentifier.getPubKey(r2Data.issuerId).flatMap { pubKey =>
//        tallyR2.verifyRound2Data(pubKey, r2Data, dkgR1DataAll).toOption
//      }.isDefined
//    }
//
//    require(tallyR2.executeRound2(verifiedR2DataAll, ballots).isSuccess)
//    tallyR2.generateR3Data((secretKey, publicKey)).get
//  }
//
//  def doTallyR4(tallyR3DataAll: Seq[TALLY#R3DATA],
//                dkgR1DataAll: Seq[R1Data]): Try[TALLY#R4DATA] = Try {
//    val tallyR3 = tally.get
//    val r3DataAll = tallyR3DataAll.map(_.asInstanceOf[tallyR3.R3DATA])
//
//    val verifiedR3DataAll = r3DataAll.filter { r3Data =>
//      memberIdentifier.getPubKey(r3Data.issuerId).flatMap { pubKey =>
//        tallyR3.verifyRound3Data(pubKey, r3Data).toOption
//      }.isDefined
//    }
//
//    require(tallyR3.executeRound3(verifiedR3DataAll).isSuccess)
//    tallyR3.generateR4Data((secretKey, publicKey), dkgR1DataAll).get
//  }
//
//  def finalizeTally(tallyR4DataAll: Seq[TALLY#R4DATA], dkgR1DataAll: Seq[R1Data]): Try[TALLY#RESULT] = Try {
//    val tallyR4 = tally.get
//    val r4DataAll = tallyR4DataAll.map(_.asInstanceOf[tallyR4.R4DATA])
//
//    val verifiedR4DataAll = r4DataAll.filter { r4Data =>
//      memberIdentifier.getPubKey(r4Data.issuerId).flatMap { pubKey =>
//        tallyR4.verifyRound4Data(pubKey, r4Data, dkgR1DataAll).toOption
//      }.isDefined
//    }
//
//    require(tallyR4.executeRound4(verifiedR4DataAll).isSuccess)
//    tallyResult = tallyR4.getResult.toOption
//    tallyResult.get
//  }
//
//  def getTallyResult = tallyResult
}