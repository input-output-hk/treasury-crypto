package io.iohk.protocol.keygen

import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.protocol.keygen.datastructures.round1.{R1Data, SecretShare}
import io.iohk.protocol.keygen.datastructures.round2.{ComplaintR2, R2Data}
import io.iohk.protocol.keygen.datastructures.round3.R3Data
import io.iohk.protocol.keygen.datastructures.round4.{ComplaintR4, OpenedShare, R4Data}
import io.iohk.protocol.keygen.datastructures.round5_1.R5_1Data
import io.iohk.protocol.keygen.datastructures.round5_2.R5_2Data
import io.iohk.protocol.tally.datastructures.{TallyR1Data, TallyR2Data, TallyR3Data, TallyR4Data}
import io.iohk.protocol.tally.{BallotsSummator, Tally}
import io.iohk.protocol.voting.ballots.{ExpertBallot, VoterBallot}
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}

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
class CommitteeMember(val ctx: CryptoContext,
                      val transportKeyPair: KeyPair,
                      val committeeMembersPubKeys: Seq[PubKey],
                      val numberOfExperts: Int,
                      roundsData: RoundsData = RoundsData()) {
  import ctx.group

  val memberIdentifier = new CommitteeIdentifier(committeeMembersPubKeys)

  // TODO: transport key pair serves also as a key pair for generating shared key. Originally these pairs were designed to be different.
  val secretKey = transportKeyPair._1
  val publicKey = transportKeyPair._2

  // DistrKeyGen instance is used to run distributed key generation protocol
  val seed = ctx.hash.hash(secretKey.toByteArray ++ "DKG Seed".getBytes) // TODO: secretKey should not be used to extract seed
  private val dkg = new DistrKeyGen(ctx, transportKeyPair, secretKey, seed, committeeMembersPubKeys, memberIdentifier, roundsData)
  private var dkgViolatorsKeys: Option[Map[PubKey, Option[PrivKey]]] = None

  // Tally should be initialized after DKG is finished, because it requires keys of committee members disqualified during DKG
  private var tally: Option[Tally] = None
  private var tallyResult: Option[Map[Int,Tally.Result]] = None // decrypted results of voting for each proposal (map of proposalId -> Result)
  private val summator = new BallotsSummator(ctx, numberOfExperts) //TODO: probably we should pass summator as an input param

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


  /* Tally stage. It should be started only when all rounds of DKG are executed. */

  def doTallyR1(ballots: Seq[VoterBallot]): Try[TallyR1Data] = Try {
    ballots.foreach(summator.addVoterBallot(_).get)

    val newTally = new Tally(ctx, memberIdentifier, numberOfExperts, dkgViolatorsKeys.get)
    tally = Some(newTally)

    newTally.generateR1Data(summator, (secretKey, publicKey)).get
  }

  def doTallyR2(tallyR1DataAll: Seq[TallyR1Data], dkgR1DataAll: Seq[R1Data]): Try[TallyR2Data] = Try {
    val tallyR1 = tally.get
    val verifiedR1DataAll = tallyR1DataAll.filter { r1Data =>
      memberIdentifier.getPubKey(r1Data.issuerID).flatMap { pubKey =>
        tallyR1.verifyRound1Data(summator, pubKey, r1Data).toOption
      }.isDefined
    }

    require(tallyR1.executeRound1(summator, verifiedR1DataAll).isSuccess)
    tallyR1.generateR2Data((secretKey, publicKey), dkgR1DataAll).get
  }

  def doTallyR3(tallyR2DataAll: Seq[TallyR2Data],
                dkgR1DataAll: Seq[R1Data],
                expertBallots: Seq[ExpertBallot]): Try[TallyR3Data] = Try {
    val tallyR2 = tally.get
    val verifiedR2DataAll = tallyR2DataAll.filter { r2Data =>
      memberIdentifier.getPubKey(r2Data.issuerID).flatMap { pubKey =>
        tallyR2.verifyRound2Data(pubKey, r2Data, dkgR1DataAll).toOption
      }.isDefined
    }

    require(tallyR2.executeRound2(verifiedR2DataAll, expertBallots).isSuccess)
    tallyR2.generateR3Data((secretKey, publicKey)).get
  }

  def doTallyR4(tallyR3DataAll: Seq[TallyR3Data],
                dkgR1DataAll: Seq[R1Data]): Try[TallyR4Data] = Try {
    val tallyR3 = tally.get
    val verifiedR3DataAll = tallyR3DataAll.filter { r3Data =>
      memberIdentifier.getPubKey(r3Data.issuerID).flatMap { pubKey =>
        tallyR3.verifyRound3Data(pubKey, r3Data).toOption
      }.isDefined
    }

    require(tallyR3.executeRound3(verifiedR3DataAll).isSuccess)
    tallyR3.generateR4Data((secretKey, publicKey), dkgR1DataAll).get
  }

  def finalizeTally(tallyR4DataAll: Seq[TallyR4Data], dkgR1DataAll: Seq[R1Data]): Try[Map[Int, Tally.Result]] = Try {
    val tallyR4 = tally.get
    val verifiedR4DataAll = tallyR4DataAll.filter { r4Data =>
      memberIdentifier.getPubKey(r4Data.issuerID).flatMap { pubKey =>
        tallyR4.verifyRound4Data(pubKey, r4Data, dkgR1DataAll).toOption
      }.isDefined
    }

    require(tallyR4.executeRound4(verifiedR4DataAll).isSuccess)
    tallyResult = Some(tallyR4.getChoices)
    tallyResult.get
  }

  def getTallyResult = tallyResult
}