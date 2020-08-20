package io.iohk.protocol.keygen

import io.iohk.core.crypto.encryption
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen.datastructures.round1.R1DataSerializer
import io.iohk.protocol.keygen.datastructures.round2.R2DataSerializer
import io.iohk.protocol.keygen.datastructures.round3.R3DataSerializer
import io.iohk.protocol.keygen.datastructures.round4.R4DataSerializer
import io.iohk.protocol.keygen.datastructures.round5_1.R5_1DataSerializer
import io.iohk.protocol.keygen.datastructures.round5_2.R5_2DataSerializer
import io.iohk.protocol.voting.approval.ApprovalContext
import org.scalatest.FunSuite

class DataStructuresTest extends FunSuite {

  test("DKG round data serialization") {

    val crs = CryptoContext.generateRandomCRS
    val ctx = new CryptoContext(Option(crs))
    import ctx.group

    val keyPairs = for(id <- 1 to 10) yield encryption.createKeyPair.get
    val committeeMembersPubKeys = keyPairs.map(_._2)

    val committeeMembers = for (i <- committeeMembersPubKeys.indices) yield {
      new CommitteeMember(ctx, keyPairs(i), committeeMembersPubKeys)
    }

    val r1Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).doDKGRound1().get
    }

//    val r1Data1 = r1Data(0)
//    val r1Data1Restored = R1DataSerializer.parseBytes(r1Data1.bytes, ctx).get
//    assert(r1Data1.equals(r1Data1Restored))

    val r1DataRestored = r1Data.map(d => R1DataSerializer.parseBytes(d.bytes, Option(ctx.group, ctx.blockCipher)).get).toArray
    assert(r1DataRestored.sameElements(r1Data))

    val r2Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).doDKGRound2(r1DataRestored).get
    }

    val r2DataRestored = r2Data.map(d => R2DataSerializer.parseBytes(d.bytes, Option(ctx.group, ctx.blockCipher)).get).toArray
    assert(r2DataRestored.sameElements(r2Data))

    val r3Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).doDKGRound3(r2Data).get
    }

    val r3DataRestored = r3Data.map(d => R3DataSerializer.parseBytes(d.bytes, Option(ctx)).get).toArray
    assert(r3DataRestored.sameElements(r3Data))

    val r4Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).doDKGRound4(r3Data).get
    }

    val r4DataRestored = r4Data.map(d => R4DataSerializer.parseBytes(d.bytes, Option(ctx.group)).get).toArray
    assert(r4DataRestored.sameElements(r4Data))

    val r5_1Data = for (i <- committeeMembersPubKeys.indices) yield {
      committeeMembers(i).doDKGRound5_1(r4Data).get
    }

    val r5_1DataRestored = r5_1Data.map(d => R5_1DataSerializer.parseBytes(d.bytes, Option(ctx.group)).get).toArray
    assert(r5_1DataRestored.sameElements(r5_1Data))

    val r5_2Data = for (i <- committeeMembersPubKeys.indices) yield {
      (committeeMembers(i).ownId, committeeMembers(i).doDKGRound5_2(r5_1Data).get)
    }

    val r5_2DataRestored = r5_2Data.map(d => R5_2DataSerializer.parseBytes(d._2.bytes, Option(ctx)).get).toArray
    assert(r5_2DataRestored.sameElements(r5_2Data.map(_._2)))

    //--------------------------------------------------------------------------------
    val sharedPublicKeys = r5_2Data.map(_._2.sharedPublicKey).map(group.reconstructGroupElement(_).get)

    val individualPublicKeys = for(i <- committeeMembers.indices) yield {
      (committeeMembers(i).ownId, group.groupGenerator.pow(committeeMembers(i).secretKey).get)
    }
    val publicKeysSum = individualPublicKeys.map(_._2).foldLeft(group.groupIdentity){(publicKeysSum, publicKey) => publicKeysSum.multiply(publicKey).get}

    assert(publicKeysSum.equals(sharedPublicKeys(0)))

  }
}
