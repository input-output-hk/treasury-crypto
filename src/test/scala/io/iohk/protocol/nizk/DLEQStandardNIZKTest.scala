package io.iohk.protocol.nizk

import io.iohk.core.crypto.encryption._
import io.iohk.core.crypto.encryption.elgamal.ElGamalEnc
import io.iohk.protocol.CryptoContext
import org.scalatest.FunSuite

class DLEQStandardNIZKTest extends FunSuite {

  val ctx = new CryptoContext(None)
  implicit val group = ctx.group
  implicit val hash = ctx.hash

  test("dleq nizk") {
    val G1 = group.createRandomGroupElement.get
    val G2 = group.createRandomGroupElement.get
    val witness = group.createRandomNumber
    val H1 = G1.pow(witness).get
    val H2 = G2.pow(witness).get

    val proof = DLEQStandardNIZK.produceNIZK(H1,H2,G1,G2,witness).get
    assert(DLEQStandardNIZK.verifyNIZK(H1,H2,G1,G2, proof))

    val proof2 = DLEQStandardNIZK.produceNIZK(H1,H2,G1,G2,witness,Option(BigInt(3))).get
    assert(DLEQStandardNIZK.verifyNIZK(H1,H2,G1,G2, proof2))

    val corruptedProof = DLEQStandardNIZKProof(proof.A1, proof.A2, proof.z + 1)
    assert(!DLEQStandardNIZK.verifyNIZK(H1,H2,G1,G2,corruptedProof))

    // incorrect args
    assert(!DLEQStandardNIZK.verifyNIZK(H2,H1,G1,G2,proof))
    assert(!DLEQStandardNIZK.verifyNIZK(H1,H2,G2,G1,proof))
    assert(!DLEQStandardNIZK.verifyNIZK(H1,H2,G1,G2.pow(2).get,proof))
    assert(!DLEQStandardNIZK.verifyNIZK(H1.multiply(G1).get,H2,G1,G2, proof))
    assert(!DLEQStandardNIZK.verifyNIZK(H1.pow(2).get,H2.pow(2).get,G1,G2, proof))
    assert(!DLEQStandardNIZK.verifyNIZK(H1.pow(2).get,H2.pow(2).get,G1.pow(2).get,G2.pow(2).get, proof))

  }

  test("serialization") {
    val G1 = group.createRandomGroupElement.get
    val G2 = group.createRandomGroupElement.get
    val witness = group.createRandomNumber
    val H1 = G1.pow(witness).get
    val H2 = G2.pow(witness).get

    val bytes = DLEQStandardNIZK.produceNIZK(H1,H2,G1,G2,witness).get.bytes
    val proof = DLEQStandardNIZKProofSerializer.parseBytes(bytes, Option(group)).get

    assert(DLEQStandardNIZK.verifyNIZK(H1,H2,G1,G2, proof))
  }
}
