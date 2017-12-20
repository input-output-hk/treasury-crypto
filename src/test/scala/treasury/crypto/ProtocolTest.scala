package treasury.crypto

import org.scalatest.FunSuite
import treasury.crypto.core.{Cryptosystem, PubKey, VoteCases, Zero}
import treasury.crypto.keygen._
import treasury.crypto.voting.{Expert, RegularVoter, Tally}

class ProtocolTest extends FunSuite {

  def doTest(cs: Cryptosystem, elections: Elections): Boolean = {
    val crs_h = cs.basePoint.multiply(cs.getRand)

    // Generating keypairs for every commitee member
    val keyPairs = for(id <- 1 to 10) yield cs.createKeyPair
    val committeeMembersPubKeys = keyPairs.map(_._2)

    // Instantiating committee members
    //
    val committeeMembers = for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(cs, crs_h, keyPairs(i), committeeMembersPubKeys)
    }

    // Generating shared public key by committee members (by running the DKG protocol between them)
    val sharedPubKey = getSharedPublicKey(cs, committeeMembers)

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
    val tallyResults = committeeMembersR2.map(_.decryptTallyR3(decryptedC1ForChoices, skSharesR2))

    assert(tallyResults.forall(_.equals(tallyResults.head)))

    val distributedDecryption = elections.verify(tallyResults.head)

    // DKG recovered secret keys taken from an arbitrary commitee member (this data is broadcasted by all committee members during DKG stage)
    val dgkRecoveredKeys = committeeMembersR2(0).dkgViolatorsIds.toSeq.zip(committeeMembersR2(0).dkgViolatorsSKs)

    // Verification of the elections results by regular member
    val tallyResult = Tally.countVotes(cs, ballots, decryptedC1ForDelegations, decryptedC1ForChoices, dgkRecoveredKeys, skSharesR1, skSharesR2)

    val individualDecryption = elections.verify(tallyResult)

    val identicalResults = tallyResults.forall(_.equals(tallyResult))

    distributedDecryption && individualDecryption && identicalResults
  }

  test("test protocol") {

    val cs = new Cryptosystem

    assert(doTest(cs, ElectionsScenario1(cs)))
    assert(doTest(cs, ElectionsScenario2(cs)))
  }
}
