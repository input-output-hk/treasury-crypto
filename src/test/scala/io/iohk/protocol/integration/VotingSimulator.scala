package io.iohk.protocol.integration

import io.iohk.core.crypto.encryption.{PrivKey, PubKey}
import io.iohk.protocol.keygen.CommitteeMember
import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.keygen.datastructures.round3.R3Data
import io.iohk.protocol.voting.common.Tally
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}

import scala.util.{Random, Try}

trait VotingSimulator {
  type RESULT

  def runVoting: Try[RESULT]
  def verify(r: RESULT): Boolean
}

object DistributedKeyGenerationSimulator {

  def runDKG(ctx: CryptoContext, committeeMembers: Seq[CommitteeMember]): (PubKey, Seq[R1Data], Map[PubKey, Option[PrivKey]]) = {
    val r1Data    = committeeMembers.tail.map(_.doDKGRound1().get) // simulate one faulty member
    val r2Data    = committeeMembers.tail.map(_.doDKGRound2(r1Data).get)
    val r3Data    = committeeMembers.tail.map(_.doDKGRound3(r2Data).get)

    val indexesToPatch = List(1,2)
    val r3DataPatched = patchR3Data(ctx, r3Data, indexesToPatch)
    //    val r3DataPatched = r3Data

    val r4Data    = committeeMembers.tail.map(_.doDKGRound4(r3DataPatched).get)
    val r5_1Data  = committeeMembers.tail.map(_.doDKGRound5_1(r4Data).get)
    val r5_2Data  = committeeMembers.tail.map(_.doDKGRound5_2(r5_1Data).get)

    val sharedPublicKeys = r5_2Data.map(_.sharedPublicKey).map(ctx.group.reconstructGroupElement(_).get)
    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys.head)))

    val disqualified = committeeMembers.tail.map(_.dkgViolatorsKeys.get)
    assert(disqualified.zipWithIndex.forall { case (d,i) =>
      if (!indexesToPatch.contains(i)) d.size == disqualified.head.size
      else true
    })

    (sharedPublicKeys.head, r1Data, disqualified.head)
  }

  def patchR3Data(ctx: CryptoContext, r3Data: Seq[R3Data], indexesToPatch: List[Int]): Seq[R3Data] = {
    val r3DataPatched = r3Data

    for(i <- r3Data.indices)
      if(indexesToPatch.contains(i))
        r3DataPatched(i).commitments(0) = ctx.group.groupIdentity.bytes

    r3DataPatched
  }
}

abstract class TallySimulator {

  type TALLY <: Tally
  type PCTX
  type RESULT = tally.RESULT

  val pctx: PCTX
  val tally: TALLY
  val summator: tally.SUMMATOR
  val expertBallots: Seq[tally.EXPERTBALLOT]

  def runTally(identifier: CommitteeIdentifier,
               committee: Seq[CommitteeMember],
               dkgR1DataAll: Seq[R1Data]): Try[RESULT] = Try {

    // let's simulate 1 failed CM at each round
    // Round 1
    val r1DataAll = committee.drop(1).map(c => tally.generateR1Data(summator, (c.secretKey, c.publicKey)).get)
    val verifiedR1DataAll = r1DataAll.filter { r1Data =>
      identifier.getPubKey(r1Data.issuerId).map { pubKey =>
        tally.verifyRound1Data(summator, pubKey, r1Data)
      }.getOrElse(false)
    }
    require(tally.executeRound1(summator, verifiedR1DataAll).isSuccess)

    // Round 2
    val r2DataAll = committee.drop(2).map(c => tally.generateR2Data((c.secretKey, c.publicKey), dkgR1DataAll).get)
    val verifiedR2DataAll = r2DataAll.filter { r2Data =>
      identifier.getPubKey(r2Data.issuerId).map { pubKey =>
        tally.verifyRound2Data(pubKey, r2Data, dkgR1DataAll).isSuccess
      }.getOrElse(false)
    }
    require(tally.executeRound2(verifiedR2DataAll, expertBallots).isSuccess)

    // Round 3
    val r3DataAll = committee.drop(3).map(c => tally.generateR3Data((c.secretKey, c.publicKey)).get)
    val verifiedR3DataAll = r3DataAll.filter { r3Data =>
      identifier.getPubKey(r3Data.issuerId).map { pubKey =>
        tally.verifyRound3Data(pubKey, r3Data).isSuccess
      }.getOrElse(false)
    }
    require(tally.executeRound3(verifiedR3DataAll).isSuccess)

    // Round 4
    val r4DataAll = committee.drop(4).map(c => tally.generateR4Data((c.secretKey, c.publicKey), dkgR1DataAll).get)
    val verifiedR4DataAll = r4DataAll.filter { r4Data =>
      identifier.getPubKey(r4Data.issuerId).map { pubKey =>
        tally.verifyRound4Data(pubKey, r4Data, dkgR1DataAll).isSuccess
      }.getOrElse(false)
    }
    require(tally.executeRound4(verifiedR4DataAll).isSuccess)

    tally.getResult.get
  }
}