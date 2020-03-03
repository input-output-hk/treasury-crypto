package io.iohk.core.crypto.primitives.hash

import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes
import org.scalatest.prop.TableDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import io.iohk.core.crypto.primitives.hash.CryptographicHashFactory.AvailableHashes

class CryptographicHashTest extends PropSpec with TableDrivenPropertyChecks with Matchers {

  val hashes =
    Table(
      "hash",
      AvailableHashes.values.toSeq.map(h => CryptographicHashFactory.constructHash(h).get):_*
    )

  property("any hash function should produce the same hash for the same message") {
    forAll(hashes) { hash =>
      val msg = "Msg to Hash"
      val sameMsg = "Msg to Hash"
      val d1 = hash.hash(msg.getBytes)
      val d2 = hash.hash(sameMsg.getBytes)

      d1.sameElements(d2) should be (true)
    }
  }

  property("any hash function should produce different hashes for different messages") {
    forAll(hashes) { hash =>
      val msg = "Msg to Hash"
      val anotherMsg = "Msg to Hash!"
      val d1 = hash.hash(msg.getBytes)
      val d2 = hash.hash(anotherMsg.getBytes)

      d1.sameElements(d2) should be (false)
    }
  }

  property("any hash function should produce hashes of the expected size") {
    forAll(hashes) { hash =>
      val d = hash.hash("msg".getBytes)
      d.size should be (hash.digestSize)
    }
  }
}
