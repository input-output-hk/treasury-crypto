package io.iohk.protocol

import io.iohk.core.utils.TimeUtils
import org.scalatest.FunSuite

import scala.util.{Failure, Try}

class IdentifierTest extends FunSuite {
  test("experts identifier") {
    val ctx = new CryptoContext(None)
    val keys = for (i <- 0 until 10) yield ctx.group.createRandomGroupElement.get
    val identifier = new ExpertIdentifier(keys)

    for (i <- 0 until 10) {
      val pubkey = identifier.getPubKey(i)
      val id = identifier.getId(pubkey.get)
      assert(i == id.get)
    }
  }

  test("committee identifier") {
    val ctx = new CryptoContext(None)
    val keys = for (i <- 0 until 10) yield ctx.group.createRandomGroupElement.get
    val identifier = new CommitteeIdentifier(keys)

    for (i <- 0 until 10) {
      val pubkey = identifier.getPubKey(i)
      val id = identifier.getId(pubkey.get)
      assert(i == id.get)
    }
  }

  test("public key duplicates") {
    val ctx = new CryptoContext(None)
    val keys = for (i <- 0 until 10) yield ctx.group.createRandomGroupElement.get

    Try(new ExpertIdentifier(keys :+ keys.head)) match {
      case Failure(e) => require(e.getMessage.contains("All public keys should be distinct!"))
      case _ => throw new Exception("Public key duplicates test failed")
    }

    Try(new CommitteeIdentifier(keys :+ keys.head)) match {
      case Failure(e) => require(e.getMessage.contains("All public keys should be distinct!"))
      case _ => throw new Exception("Public key duplicates test failed")
    }
  }

  test("experts identifier performance") {
    val ctx = new CryptoContext(None)
    val keys = TimeUtils.time_ms("Keys generation: ", for (i <- 0 until 1000) yield ctx.group.createRandomGroupElement.get)
    val identifier = TimeUtils.time_ms("Identifier creation: ", new ExpertIdentifier(keys))

    TimeUtils.time_ms("Extract key by id first time: ", identifier.getPubKey(0))
    TimeUtils.time_ms("Extract key by id second time: ", identifier.getPubKey(6))

    TimeUtils.time_ms("Extract id by pubkey first time: ", identifier.getId(keys.head))
    TimeUtils.time_ms("Extract id by pubkey second time: ", identifier.getId(keys.head))
  }
}
