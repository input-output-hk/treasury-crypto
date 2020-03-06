package io.iohk.protocol

import io.iohk.core.crypto.encryption
import io.iohk.protocol.keygen._
import org.scalatest.FunSuite

class ProtocolTest extends FunSuite {

  def doTest(ctx: CryptoContext, elections: Elections): Boolean = {
    import ctx.{group, hash}

    // Generating keypairs for every commitee member
    val keyPairs = Array.fill(10)(encryption.createKeyPair.get)
    val committeeMembersPubKeys = keyPairs.map(_._2)

    // Instantiating committee members
    //
    val committeeMembers = keyPairs.map(k => new CommitteeMember(ctx, k, committeeMembersPubKeys))

    // Generating shared public key by committee members (by running the DKG protocol between them)
    val sharedPubKey = getSharedPublicKey(ctx, committeeMembers)

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
