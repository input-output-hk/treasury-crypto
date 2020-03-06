package io.iohk.protocol.integration

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen._
import io.iohk.protocol.keygen.datastructures.round3.R3Data
import org.scalatest.FunSuite

import scala.util.Random

/**
  * Integration test for all components of the voting protocol: distributed key generation + ballots encryption and voting +
  * tally calculation and decryption
  */
class ProtocolTest extends FunSuite {

  def doTest(ctx: CryptoContext, elections: Elections): Boolean = {
    import ctx.group

    // Generating keypairs for every commitee member
    val keyPairs = Array.fill(10)(encryption.createKeyPair.get)
    val committeeMembersPubKeys = keyPairs.map(_._2)

    // Instantiating committee members
    //
    val committeeMembers = keyPairs.map(k => new CommitteeMember(ctx, k, committeeMembersPubKeys))

    // Generating shared public key by committee members (by running the DKG protocol between them)
    val sharedPubKey = ProtocolTest.getSharedPublicKey(ctx, committeeMembers)

    // Running elections by specific scenario
    val ballots = elections.run(sharedPubKey)

    val R1_ABSENTEES_NUM = 2
    val R2_ABSENTEES_NUM = 2

    // Imitation of the disappearance from the delegations decryption phase the R1_ABSENTEES_NUM number of commitee members
    val committeeMembersR1 = committeeMembers.take(committeeMembers.length - R1_ABSENTEES_NUM)

    // Joint decryption of the delegations C1-keys by committee members
    val decryptedC1ForDelegations = committeeMembersR1.map(_.decryptTallyR1(ballots))

    // Publishing secret key shares of absent commitee members on delegations decryption phase
    val skSharesR1 = committeeMembersR1.map(_.keysRecoveryR1(decryptedC1ForDelegations))

    // Imitation of the disappearance from the choises decryption phase the R2_ABSENTEES_NUM number of commitee members
    val committeeMembersR2 = committeeMembersR1.take(committeeMembersR1.length - R2_ABSENTEES_NUM)

    // Joint decryption of the votes C1-keys by committee members
    val decryptedC1ForChoices = committeeMembersR2.map(_.decryptTallyR2(decryptedC1ForDelegations, skSharesR1))

    // Publishing secret key shares of absent commitee members on choises decryption phase
    val skSharesR2 = committeeMembersR2.map(_.keysRecoveryR2(decryptedC1ForChoices))

    // Joint decryption of the tally by committee members
    val tallyResults = committeeMembersR2.map(_.decryptTallyR3(decryptedC1ForChoices, skSharesR1, skSharesR2))

    assert(tallyResults.forall(_.equals(tallyResults.head)))

    val distributedDecryption = elections.verify(tallyResults.head)

    // DKG recovered secret keys taken from an arbitrary commitee member (this data is broadcasted by all committee members during DKG stage)
    val dgkRecoveredKeys = committeeMembersR2(0).dkgViolatorsIds.toSeq.zip(committeeMembersR2(0).dkgViolatorsSKs)

    // Verification of the elections results
    val identicalResults = tallyResults.forall(elections.verify)

    distributedDecryption && identicalResults
  }

  test("test protocol") {
    val crs = CryptoContext.generateRandomCRS
    val ctx = new CryptoContext(Option(crs))

    assert(doTest(ctx, ElectionsScenario1(ctx)))
    assert(doTest(ctx, ElectionsScenario2(ctx)))
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

  def getSharedPublicKey(ctx: CryptoContext, committeeMembers: Seq[CommitteeMember]): PubKey = {
    val r1Data    = committeeMembers.map(_.setKeyR1   ())
    val r2Data    = committeeMembers.map(_.setKeyR2   (r1Data))
    val r3Data    = committeeMembers.map(_.setKeyR3   (r2Data))

    val r3DataPatched = patchR3Data(ctx, r3Data, 1)
    //    val r3DataPatched = r3Data

    val r4Data    = committeeMembers.map(_.setKeyR4   (r3DataPatched))
    val r5_1Data  = committeeMembers.map(_.setKeyR5_1 (r4Data))
    val r5_2Data  = committeeMembers.map(_.setKeyR5_2 (r5_1Data))

    val sharedPublicKeys = r5_2Data.map(_.sharedPublicKey).map(ctx.group.reconstructGroupElement(_).get)

    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys.head)))
    sharedPublicKeys.head
  }
}
