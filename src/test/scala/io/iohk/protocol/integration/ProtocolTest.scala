package io.iohk.protocol.integration

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen._
import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.keygen.datastructures.round3.R3Data
import io.iohk.protocol.voting.approval.multi_delegation.{MultiDelegExpertBallot, MultiDelegVoterBallot}
import org.scalatest.FunSuite

import scala.util.Random

/**
  * Integration test for all components of the voting protocol: distributed key generation + ballots encryption and voting +
  * tally calculation and decryption
  */
class ProtocolTest extends FunSuite {

  def doTest(elections: Elections): Boolean = {
    val ctx = elections.getContext

    // Generating keypairs for every commitee member
    val keyPairs = Array.fill(20)(encryption.createKeyPair(ctx.cryptoContext.group).get)
    val committeeMembersPubKeys = keyPairs.map(_._2)

    // Instantiating committee members
    val committeeMembers = keyPairs.map(k => new CommitteeMember(ctx, k, committeeMembersPubKeys))

    // Generating shared public key by running the DKG protocol among committee members
    val (sharedPubKey, dkgR1DataAll) = ProtocolTest.runDistributedKeyGeneration(ctx.cryptoContext, committeeMembers)

    // Running elections by specific scenario
    val (voterBallots, expertBallots) = elections.run(sharedPubKey)

    val tallyResults = ProtocolTest.runTally(committeeMembers, voterBallots, expertBallots, dkgR1DataAll)
    elections.verify(tallyResults)
  }

  test("test full protocol") {
    val crs = CryptoContext.generateRandomCRS
    val ctx = new CryptoContext(Option(crs))

    require(doTest(new ElectionsScenario1(ctx)))
    require(doTest(new ElectionsScenario2(ctx)))
    require(doTest(new ElectionsScenario3(ctx)))
    require(doTest(new ElectionsScenario4(ctx)))
  }
}

object ProtocolTest {

  def patchR3Data(ctx: CryptoContext, r3Data: Seq[R3Data], numOfPatches: Int): Seq[R3Data] = {
    require(numOfPatches <= r3Data.length)

    var r3DataPatched = r3Data

    var indexesToPatch = Array.fill[Boolean](numOfPatches)(true) ++ Array.fill[Boolean](r3Data.length - numOfPatches)(false)
    indexesToPatch = Random.shuffle(indexesToPatch.toSeq).toArray

    for(i <- r3Data.indices)
      if(indexesToPatch(i))
        r3DataPatched(i).commitments(0) = ctx.group.groupIdentity.bytes

    r3DataPatched
  }

  def runDistributedKeyGeneration(ctx: CryptoContext, committeeMembers: Seq[CommitteeMember]): (PubKey, Seq[R1Data]) = {
    val r1Data    = committeeMembers.map(_.doDKGRound1().get)
    val r2Data    = committeeMembers.map(_.doDKGRound2(r1Data).get)
    val r3Data    = committeeMembers.map(_.doDKGRound3(r2Data).get)

    val r3DataPatched = patchR3Data(ctx, r3Data, 1)
    //    val r3DataPatched = r3Data

    val r4Data    = committeeMembers.map(_.doDKGRound4(r3DataPatched).get)
    val r5_1Data  = committeeMembers.map(_.doDKGRound5_1(r4Data).get)
    val r5_2Data  = committeeMembers.map(_.doDKGRound5_2(r5_1Data).get)

    val sharedPublicKeys = r5_2Data.map(_.sharedPublicKey).map(ctx.group.reconstructGroupElement(_).get)

    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys.head)))
    sharedPublicKeys.head -> r1Data
  }

  def runTally(committeeMembers: Seq[CommitteeMember],
               voterBallots: Seq[MultiDelegVoterBallot],
               expertBallots: Seq[MultiDelegExpertBallot],
               dkgR1DataAll: Seq[R1Data]): Map[Int, Vector[BigInt]] = {
    // let's simulate 1 failed CM at each round
    val r1DataAll = committeeMembers.drop(1).map(_.doTallyR1(voterBallots).get)
    val r2DataAll = committeeMembers.drop(2).map(_.doTallyR2(r1DataAll, dkgR1DataAll).get)
    val r3DataAll = committeeMembers.drop(3).map(_.doTallyR3(r2DataAll, dkgR1DataAll, expertBallots).get)
    val r4DataAll = committeeMembers.drop(4).map(_.doTallyR4(r3DataAll, dkgR1DataAll).get)
    committeeMembers.drop(4).foreach(_.finalizeTally(r4DataAll, dkgR1DataAll).get)

    val result = committeeMembers.last.getTallyResult.get
    committeeMembers.drop(4).foreach(c => require(c.getTallyResult.get == result))
    result
  }
}
