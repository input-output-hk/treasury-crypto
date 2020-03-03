package io.iohk.core.primitives.dlog

import java.math.BigInteger

import io.iohk.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks

/**
  * Performs generic tests for DiscreteLogGroup interface for all available implementations of the dlog group
  */
class DiscreteLogGroupTest extends FunSuite with TableDrivenPropertyChecks {

  import DiscreteLogGroupTest.dlogGroups

  test("any group should return a non-zero group order") {
    forAll(dlogGroups) { case (groupType, group) =>
      require(group.groupOrder > 0)
    }
  }

  test("any group should have generator different from identity of the group") {
    forAll(dlogGroups) { case (groupType, group) =>
      require(group.groupGenerator.isIdentity == false)
    }
  }

  test("any group should have identity element") {
    forAll(dlogGroups) { case (groupType, group) =>
      require(group.groupIdentity.isIdentity)
    }
  }

  test("any group should be able to create valid random number") {
    forAll(dlogGroups) { case (groupType, group) =>
      val rand = group.createRandomNumber
      require(rand > 0)
      require(rand < group.groupOrder)
    }
  }

  test("any group should generate valid random group elements") {
    forAll(dlogGroups) { case (groupType, group) =>
      val e1 = group.createRandomGroupElement.get
      val e2 = group.createRandomGroupElement.get
      require(e1 != e2)
      require(group.isValidGroupElement(e1))
      require(group.isValidGroupElement(e2))
    }
  }

  test("any group should implement multiplication of the group elements") {
    forAll(dlogGroups) { case (groupType, group) =>
      val e1 = group.createRandomGroupElement.get
      val e2 = group.createRandomGroupElement.get
      val res = group.multiply(e1, e2).get

      require(res != e1)
      require(res != e2)
      require(!res.isIdentity)
    }
  }

  test("multiplication of any element with the identity element should yeild the same element") {
    forAll(dlogGroups) { case (groupType, group) =>
      val e = group.createRandomGroupElement.get
      val res = group.multiply(e, group.groupIdentity).get

      require(res == e)
    }
  }

  test("any group should implement exponentiation of the group element") {
    forAll(dlogGroups) { case (groupType, group) =>
      val res = group.exponentiate(group.groupGenerator, 5).get

      require(res != group.groupGenerator)
      require(res.isIdentity == false)

      val e = group.createRandomGroupElement.get
      val res1 = group.exponentiate(e, -5).get
      val res1_2 = group.exponentiate(e, BigInt(-5).mod(group.groupOrder)).get

      require(res1 != e)
      require(res1 == res1_2)

      val res2 = group.exponentiate(e, 2).get
      val res2_2 = group.exponentiate(e, 2 + group.groupOrder).get

      require(res2 != e)
      require(res2== res2_2)

      require(group.exponentiate(e, 254362).isSuccess)
    }
  }

  test("exponentiation to the power of 1 should yield the same element") {
    forAll(dlogGroups) { case (groupType, group) =>
      val res = group.exponentiate(group.groupGenerator, 1).get
      require(res == group.groupGenerator)

      val res2 = group.exponentiate(group.groupGenerator, 1 - group.groupOrder).get
      require(res2 == group.groupGenerator)

      val res3 = group.exponentiate(group.groupGenerator, 1 + group.groupOrder).get
      require(res3 == group.groupGenerator)
    }
  }

  test("exponentiation to the zero exponent should yield the identity element") {
    forAll(dlogGroups) { case (groupType, group) =>
      val res = group.exponentiate(group.groupGenerator, 0).get
      require(res == group.groupIdentity)
    }
  }

  test("any group should support division of the group elements") {
    forAll(dlogGroups) { case (groupType, group) =>
      val e1 = group.createRandomGroupElement.get
      val e2 = group.createRandomGroupElement.get
      val res = group.divide(e1, e2).get

      require(res != e1)
      require(res != e2)
      require(!res.isIdentity)

      val e1_1 = group.multiply(e2, res).get
      require(e1_1 == e1)

      val e2_1 = group.divide(e1, res).get
      require(e2_1 == e2)
    }
  }

  test("any group should support inverse of the group element") {
    forAll(dlogGroups) { case (groupType, group) =>
      val e = group.createRandomGroupElement.get
      val inverse = group.inverse(e).get
      require(inverse != e)

      val identity = group.multiply(e, inverse).get
      require(identity == group.groupIdentity)
    }
  }

  test("any group should create the same group element from the same seed") {
    forAll(dlogGroups) { case (groupType, group) =>
      val seed = "seed".getBytes
      val e1 = group.createGroupElementFromSeed(seed).get
      val e2 = group.createGroupElementFromSeed("seed".getBytes).get
      require(e1 == e2)

      val e3 = group.createGroupElementFromSeed("seed!".getBytes).get
      require(e3 != e2)
    }
  }

  test("verify that group params corresponds to the specification") {
    forAll(dlogGroups) { case (groupType, group) =>
      val params = GroupParameters.getGroupParameters(groupType)
      require(group.groupGenerator.toString.toLowerCase == params.generator.toLowerCase)
      require(group.groupOrder == BigInt(new BigInteger(params.order, 16)))
    }
  }

  test("any group should be able to reconstruct an element from bytes") {
    forAll(dlogGroups) { case (groupType, group) =>
      val e = group.createRandomGroupElement.get
      val e_reconstructed = group.reconstructGroupElement(e.bytes).get
      require(e == e_reconstructed)

      val iden = group.groupIdentity
      val iden_reconstructed = group.reconstructGroupElement(iden.bytes).get
      require(iden == iden_reconstructed)
    }
  }
}

object DiscreteLogGroupTest extends TableDrivenPropertyChecks {

  val dlogGroups =
    Table(
      "group",
      AvailableGroups.values.toSeq.map(g => (g, DiscreteLogGroupFactory.constructDlogGroup(g).get)):_*
    )
}
