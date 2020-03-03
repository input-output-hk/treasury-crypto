package io.iohk.protocol.keygen

import io.iohk.common.VotingSimulator
import io.iohk.protocol.Cryptosystem
import io.iohk.protocol.keygen.datastructures.C1ShareSerializer
import io.iohk.protocol.keygen.datastructures.round1.R1DataSerializer
import io.iohk.protocol.keygen.datastructures.round2.R2DataSerializer
import io.iohk.protocol.keygen.datastructures.round3.R3DataSerializer
import io.iohk.protocol.keygen.datastructures.round4.R4DataSerializer
import io.iohk.protocol.keygen.datastructures.round5_1.R5_1DataSerializer
import io.iohk.protocol.keygen.datastructures.round5_2.R5_2DataSerializer
import org.scalatest.FunSuite

class DataStructuresTest extends FunSuite {

  test("DKG round data serialization") {

    val cs = new Cryptosystem
    import cs.{group, hash}

    val crs_h = cs.basePoint.pow(cs.getRand).get

    val keyPairs = for(id <- 1 to 10) yield cs.createKeyPair
    val committeeMembersPubKeys = keyPairs.map(_._2)

    val committeeMembers = for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(cs, crs_h, keyPairs(i), committeeMembersPubKeys)
    }

    val r1Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR1()
    }

//    val r1Data1 = r1Data(0)
//    val r1Data1Restored = R1DataSerializer.parseBytes(r1Data1.bytes, cs).get
//    assert(r1Data1.equals(r1Data1Restored))

    val r1DataRestored = r1Data.map(d => R1DataSerializer.parseBytes(d.bytes, Option(cs.group, cs.blockCipher)).get).toArray
    assert(r1DataRestored.sameElements(r1Data))

    val r2Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR2(r1DataRestored)
    }

    val r2DataRestored = r2Data.map(d => R2DataSerializer.parseBytes(d.bytes, Option(cs.group, cs.blockCipher)).get).toArray
    assert(r2DataRestored.sameElements(r2Data))

    val r3Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR3(r2Data)
    }

    val r3DataRestored = r3Data.map(d => R3DataSerializer.parseBytes(d.bytes, Option(cs)).get).toArray
    assert(r3DataRestored.sameElements(r3Data))

    val r4Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR4(r3Data)
    }

    val r4DataRestored = r4Data.map(d => R4DataSerializer.parseBytes(d.bytes, Option(cs.group)).get).toArray
    assert(r4DataRestored.sameElements(r4Data))

    val r5_1Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).setKeyR5_1(r4Data)
    }

    val r5_1DataRestored = r5_1Data.map(d => R5_1DataSerializer.parseBytes(d.bytes, Option(cs.group)).get).toArray
    assert(r5_1DataRestored.sameElements(r5_1Data))

    val r5_2Data = for (i <- committeeMembersPubKeys.indices) yield {
      (committeeMembers(i).ownId, committeeMembers(i).setKeyR5_2(r5_1Data))
    }

    val r5_2DataRestored = r5_2Data.map(d => R5_2DataSerializer.parseBytes(d._2.bytes, Option(cs)).get).toArray
    assert(r5_2DataRestored.sameElements(r5_2Data.map(_._2)))

    //--------------------------------------------------------------------------------
    val sharedPublicKeys = r5_2Data.map(_._2.sharedPublicKey).map(cs.decodePoint)

    var individualPublicKeys = for(i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, cs.basePoint.pow(committeeMembers(i).secretKey).get)
    }
    val publicKeysSum = individualPublicKeys.map(_._2).foldLeft(cs.infinityPoint){(publicKeysSum, publicKey) => publicKeysSum.multiply(publicKey).get}

    assert(publicKeysSum.equals(sharedPublicKeys(0)))

  }

  test("C1Share serialization") {
    val committee = 1
    val voters = 5
    val experts = 5
    val voterStake = 1

    val simulator = new VotingSimulator(committee, experts, voters, voterStake)
    val ballots = simulator.prepareVotersBallots((1, 1), voters - 1, 0, 0) ++ simulator.prepareExpertBallots(0, experts, 0)

    val decryptionSharesBytes = simulator.prepareDecryptionShares(ballots).map { case (deleg, choices) =>
      ((deleg._1, deleg._2.bytes), (choices._1, choices._2.bytes))
    }

    val decryptionShares = decryptionSharesBytes.map { case (deleg, choices) =>
      ((deleg._1, C1ShareSerializer.parseBytes(deleg._2, Option(simulator.cs.group)).get),
        (choices._1, C1ShareSerializer.parseBytes(choices._2, Option(simulator.cs.group)).get))
    }

    val verified = simulator.verifyDecryptionShares(ballots, decryptionShares)

    assert(verified)
  }
}
