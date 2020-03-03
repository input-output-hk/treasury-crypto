package io.iohk

import org.scalatest.FunSuite
import io.iohk.core.{CommitteeIdentifier, Cryptosystem, ExpertIdentifier, TimeUtils}

class IdentifierTest extends FunSuite {
  test("experts identifier") {
    val cs = new Cryptosystem
    val keys = for (i <- 0 until 10) yield cs.group.createRandomGroupElement.get
    val identifier = new ExpertIdentifier(keys)

    for (i <- 0 until 10) {
      val pubkey = identifier.getPubKey(i)
      val id = identifier.getId(pubkey.get)
      assert(i == id.get)
    }
  }

  test("committee identifier") {
    val cs = new Cryptosystem
    val keys = for (i <- 0 until 10) yield cs.group.createRandomGroupElement.get
    val identifier = new CommitteeIdentifier(keys)

    for (i <- 0 until 10) {
      val pubkey = identifier.getPubKey(i)
      val id = identifier.getId(pubkey.get)
      assert(i == id.get)
    }
  }

  test("experts identifier performance") {
    val cs = new Cryptosystem
    val keys = TimeUtils.time_ms("Keys generation: ", for (i <- 0 until 1000) yield cs.group.createRandomGroupElement.get)
    val identifier = TimeUtils.time_ms("Identifier creation: ", new ExpertIdentifier(keys))

    TimeUtils.time_ms("Extract key by id first time: ", identifier.getPubKey(0))
    TimeUtils.time_ms("Extract key by id second time: ", identifier.getPubKey(6))

    TimeUtils.time_ms("Extract id by pubkey first time: ", identifier.getId(keys.head))
    TimeUtils.time_ms("Extract id by pubkey second time: ", identifier.getId(keys.head))
  }
}
