package treasury.crypto

import java.math.BigInteger

import org.scalatest.FunSuite
import treasury.crypto.core.{Cryptosystem, PubKey, VoteCases, Zero}
import treasury.crypto.keygen.{CommitteeMember, R1Data, R3Data}
import treasury.crypto.voting.{Expert, RegularVoter, Tally}

class ProtocolTest extends FunSuite {

  def getSharedPublicKey(cs: Cryptosystem, committeeMembers: Seq[CommitteeMember]): PubKey = {

    val r1Data = for (i <- committeeMembers.indices) yield
      committeeMembers(i).setKeyR1()

    val r2Data = for (i <- committeeMembers.indices) yield
      committeeMembers(i).setKeyR2(r1Data)

    val r3Data = for (i <- committeeMembers.indices) yield
      committeeMembers(i).setKeyR3(r2Data)

    val r4Data = for (i <- committeeMembers.indices) yield
      committeeMembers(i).setKeyR4(r3Data)

    val r5_1Data = for (i <- committeeMembers.indices) yield
      committeeMembers(i).setKeyR5_1(r4Data)

    val r5_2Data = for (i <- committeeMembers.indices) yield
       committeeMembers(i).setKeyR5_2(r5_1Data)

    val sharedPublicKeys = r5_2Data.map(_.sharedPublicKey).map(cs.decodePoint)

    assert(sharedPublicKeys.forall(_.equals(sharedPublicKeys(0))))
    sharedPublicKeys(0)
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
    val decryptedC1ForDelegations = for(i <- committeeMembers.indices) yield
      committeeMembers(i).decryptC1ForDelegations(ballots)

    // Joint decryption of the votes C1-keys by committee members
    //
    val decryptedC1ForVotes = for(i <- committeeMembers.indices) yield
      committeeMembers(i).decryptC1ForVotes(ballots, decryptedC1ForDelegations)

    // Joint decryption of the tally by committee members
    //
    val tallyResults = for(i <- committeeMembers.indices) yield
      committeeMembers(i).decryptTally(decryptedC1ForVotes)

    assert(tallyResults.forall(_.equals(tallyResults.head)))

    val distributedDecryption = elections.verify(tallyResults.head)

    // Centralized verification of the elections results
    //
    val sharedSecretKey = committeeMembers.foldLeft(BigInteger.valueOf(0)){(sharedSK, currentMember) => sharedSK.add(currentMember.secretKey)}
    val tallyResult = Tally.countVotesV2(cs, ballots, sharedSecretKey)

    val centralizedDecryption = elections.verify(tallyResult)

    val identicalResults = tallyResults.forall(_.equals(tallyResult))

    distributedDecryption && centralizedDecryption && identicalResults
  }

  test("test protocol"){

    val cs = new Cryptosystem

    assert(doTest(cs, ElectionsScenario1(cs)))
    assert(doTest(cs, ElectionsScenario2(cs)))
  }
}
