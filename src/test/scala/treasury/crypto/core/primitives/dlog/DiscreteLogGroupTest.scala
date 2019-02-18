package treasury.crypto.core.dlog

import org.scalatest.{Matchers, PropSpec}
import org.scalatest.prop.TableDrivenPropertyChecks
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory
import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups

/*
 * Performs generic tests for DiscreteLogGroup inteface for all available implementations of the dlog group
 */
class DiscreteLogGroupTest extends PropSpec with TableDrivenPropertyChecks with Matchers {

  val dlogGroups =
    Table(
      "group",
      DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256k1).get
    )

  property("any group should return a non-zero group order") {
    forAll(dlogGroups) { group =>
      group.groupOrder should be > BigInt(0)
    }
  }

  property("any group should have generator different from identity of the group") {
    forAll(dlogGroups) { group =>
      group.groupGenerator.isIdentity should be (false)
    }
  }

  property("any group should have identity element") {
    forAll(dlogGroups) { group =>
      group.groupIdentity.isIdentity should be (true)
    }
  }

  property("any group should be able to create valid random number") {
    forAll(dlogGroups) { group =>
      val rand = group.createRandomNumber
      rand should be > BigInt(0)
      rand should be < group.groupOrder
    }
  }

  property("any group should implement multiplication of the group elements") {
    forAll(dlogGroups) { group =>
      val e1 = group.createRandomGroupElement.get
      val e2 = group.createRandomGroupElement.get
      val res = group.multiply(e1, e2)

      res.isSuccess should be (true)
      res.get should not equals e1
      res.get should not equals e2
      res.get.isIdentity should be (false)
    }
  }

  property("multiplication of any element with the identity element should yeild the same element") {
    forAll(dlogGroups) { group =>
      val e = group.createRandomGroupElement.get
      val res = group.multiply(e, group.groupIdentity)

      res.isSuccess should be (true)
      res.get should be (e)
    }
  }

  property("any group should implement exponentiation of the group element") {
    forAll(dlogGroups) { group =>
      val res = group.exponentiate(group.groupGenerator, 5)

      res.isSuccess should be (true)
      res.get should not equals group.groupGenerator
      res.get.isIdentity should be (false)

      val e = group.createRandomGroupElement.get
      val res1 = group.exponentiate(e, -5)
      val res1_2 = group.exponentiate(e, BigInt(-5).mod(group.groupOrder))

      require(res1.isSuccess && res1_2.isSuccess)
      res1.get should not equals (e)
      res1.get should be (res1_2.get)
    }
  }

  property("exponentiation to the neutral exponent should yield the same element") {
    forAll(dlogGroups) { group =>
      val res = group.exponentiate(group.groupGenerator, 1)

      require(res.isSuccess)
      res.get should be (group.groupGenerator)
    }
  }

  property("exponentiation to the zero exponent should yield the identity element") {
    forAll(dlogGroups) { group =>
      val res = group.exponentiate(group.groupGenerator, 0)

      require(res.isSuccess)
      res.get should be (group.groupIdentity)
    }
  }

  property("any group should support division of the group elements") {
    forAll(dlogGroups) { group =>
      val e1 = group.createRandomGroupElement.get
      val e2 = group.createRandomGroupElement.get
      val res = group.divide(e1, e2)

      res.isSuccess should be (true)
      res.get should not equals e1
      res.get should not equals e2
      res.get.isIdentity should be (false)

      val e1_1 = group.multiply(e2, res.get).get
      e1_1 should be (e1)

      val e2_1 = group.divide(e1, res.get).get
      e2_1 should be (e2)
    }
  }

  property("any group should support inverse of the group element") {
    forAll(dlogGroups) { group =>
      val e = group.createRandomGroupElement.get
      val inverse = group.inverse(e)

      inverse.isSuccess should be (true)
      inverse.get should not equals e

      val identity = group.multiply(e, inverse.get).get
      identity should be (group.groupIdentity)
    }
  }

  property("any group should create the same group element from the same seed") {
    forAll(dlogGroups) { group =>
      val seed = "seed".getBytes
      val e1 = group.createGroupElementFromSeed(seed).get
      val e2 = group.createGroupElementFromSeed("seed".getBytes).get

      e1.equals(e2) should be (true)

      val e3 = group.createGroupElementFromSeed("seed!".getBytes).get

      e3.equals(e2) should be (false)
    }
  }

  property("any group should be able to reconstruct an element from bytes") {
    forAll(dlogGroups) { group =>
      // TODO
    }
  }
}
