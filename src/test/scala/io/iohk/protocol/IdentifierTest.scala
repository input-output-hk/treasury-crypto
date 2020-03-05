package io.iohk.protocol

import io.iohk.core.utils.TimeUtils
import org.scalatest.FunSuite

class IdentifierTest extends FunSuite {
  test("experts identifier") {
    val cs = new CryptoContext(None)
    val keys = for (i <- 0 until 10) yield cs.group.createRandomGroupElement.get
    val identifier = new ExpertIdentifier(keys)

    for (i <- 0 until 10) {
      val pubkey = identifier.getPubKey(i)
      val id = identifier.getId(pubkey.get)
      assert(i == id.get)
    }
  }

  test("committee identifier") {
    val cs = new CryptoContext(None)
    val keys = for (i <- 0 until 10) yield cs.group.createRandomGroupElement.get
    val identifier = new CommitteeIdentifier(keys)

    for (i <- 0 until 10) {
      val pubkey = identifier.getPubKey(i)
      val id = identifier.getId(pubkey.get)
      assert(i == id.get)
    }
  }

  test("experts identifier performance") {
    val cs = new CryptoContext(None)
    val keys = TimeUtils.time_ms("Keys generation: ", for (i <- 0 until 1000) yield cs.group.createRandomGroupElement.get)
    val identifier = TimeUtils.time_ms("Identifier creation: ", new ExpertIdentifier(keys))

    TimeUtils.time_ms("Extract key by id first time: ", identifier.getPubKey(0))
    TimeUtils.time_ms("Extract key by id second time: ", identifier.getPubKey(6))

    TimeUtils.time_ms("Extract id by pubkey first time: ", identifier.getId(keys.head))
    TimeUtils.time_ms("Extract id by pubkey second time: ", identifier.getId(keys.head))
  }
}
