package treasury.crypto

import java.math.BigInteger

import org.scalatest.FunSuite
import treasury.crypto.core.{Cryptosystem, PubKey, VoteCases, Zero}
import treasury.crypto.keygen._
import treasury.crypto.voting.{Expert, RegularVoter, Tally}

class ProtocolTest extends FunSuite {

  def getSharedPublicKey(cs: Cryptosystem, committeeMembers: Seq[CommitteeMember]): PubKey =
  {
    val r1Data    = committeeMembers.map(_.setKeyR1   ())
    val r2Data    = committeeMembers.map(_.setKeyR2   (r1Data))
    val r3Data    = committeeMembers.map(_.setKeyR3   (r2Data))

//    val r3DataPatched = patchR3Data(cs, r3Data, 1)
    val r3DataPatched = r3Data

    val r4Data    = committeeMembers.map(_.setKeyR4   (r3DataPatched))
    val r5_1Data  = committeeMembers.map(_.setKeyR5_1 (r4Data))
    val r5_2Data  = committeeMembers.map(_.setKeyR5_2 (r5_1Data))

    val sharedPublicKeys = r5_2Data.map(_.sharedPublicKey).map(cs.decodePoint)

    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys.head)))
    sharedPublicKeys.head
  }

  def doTest(cs: Cryptosystem, elections: Elections): Boolean =
  {
    val crs_h = cs.basePoint.multiply(cs.getRand)

    // Generating keypairs for every commitee member
    //
    val keyPairs = for(id <- 1 to 10) yield cs.createKeyPair
    val committeeMembersPubKeys = keyPairs.map(_._2)

    // Instantiating committee members
    //
    val committeeMembers = for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(cs, crs_h, keyPairs(i), committeeMembersPubKeys)
    }

    // Generating shared public key by committee members (by running the DKG protocol between them)
    //
    val sharedPubKey = getSharedPublicKey(cs, committeeMembers)

    // Running elections by specific scenario
    //
    val ballots = elections.run(sharedPubKey)

    // Joint decryption of the delegations C1-keys by committee members
    //
    val decryptedC1ForDelegations = committeeMembers.map(_.decryptTallyR1(ballots))

    // Joint decryption of the votes C1-keys by committee members
    //
    val decryptedC1ForChoices = committeeMembers.map(_.decryptTallyR2(decryptedC1ForDelegations))

    // Joint decryption of the tally by committee members
    //
    val tallyResults = committeeMembers.map(_.decryptTallyR3(decryptedC1ForChoices))

    assert(tallyResults.forall(_.equals(tallyResults.head)))

    val distributedDecryption = elections.verify(tallyResults.head)

    // Verification of the elections results by regular member
    //
    val tallyResult = Tally.countVotes(cs, ballots, decryptedC1ForDelegations, decryptedC1ForChoices)

    val individualDecryption = elections.verify(tallyResult)

    val identicalResults = tallyResults.forall(_.equals(tallyResult))

    distributedDecryption && individualDecryption && identicalResults
  }

  test("test protocol"){

    val cs = new Cryptosystem

    assert(doTest(cs, ElectionsScenario1(cs)))
    assert(doTest(cs, ElectionsScenario2(cs)))
  }
}
