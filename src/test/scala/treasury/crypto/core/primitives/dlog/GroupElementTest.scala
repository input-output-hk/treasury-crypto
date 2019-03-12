package treasury.crypto.core.primitives.dlog

import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks
import treasury.crypto.core.dlog.DiscreteLogGroupTest

/**
  * Performs generic tests for GroupElement interface for all available implementations of the dlog group
  */
class GroupElementTest extends FunSuite with TableDrivenPropertyChecks {

  import DiscreteLogGroupTest.dlogGroups

  test("any group element should support multiplication on the other group element") {
    forAll(dlogGroups) { implicit group =>
      val e1 = group.createRandomGroupElement.get
      val e2 = group.createRandomGroupElement.get
      val res1 = (e1 * e2).get
      val res2 = e1.multiply(e2).get

      require(res1 != e1)
      require(res1 != e2)
      require(!res1.isIdentity)
      require(res1 == res2)
    }
  }

  test("any group element should support division on the other group element") {
    forAll(dlogGroups) { implicit group =>
      val e1 = group.createRandomGroupElement.get
      val e2 = group.createRandomGroupElement.get

      val res1 = (e1 / e2).get
      val res2 = e1.divide(e2).get
      require(res1 == res2)

      val e2_1 = (e1 / res1).get
      val e1_1 = (e2 * res2).get
      require(e2 == e2_1)
      require(e1 == e1_1)
    }
  }

  test("any group element should support exponentiation") {
    forAll(dlogGroups) { implicit group =>
      val e = group.createRandomGroupElement.get

      val res1 = e.pow(2).get
      val res2 = (e * e).get
      val res3 = (res1 / e).get
      require(res1 != e)
      require(res1 == res2)
      require(res3 == e)

      val res4 = e.pow(0).get
      require(res4.isIdentity)

      val res5 = e.pow(1).get
      require(res5 == e)

      val res6_1 = e.pow(-1).get
      val res6_2 = e.pow(-1 + group.groupOrder).get
      val res6_3 = e.pow(-1 + (group.groupOrder * 2)).get
      require(res6_1 == res6_2)
      require(res6_1 == res6_3)
    }
  }

  test("any group element should support inversion") {
    forAll(dlogGroups) { implicit group =>
      val e = group.createRandomGroupElement.get
      val e_inv = e.inverse.get

      val e_1 = e_inv.inverse.get
      require(e == e_1)

      val e_2 = ((e / e_inv).get / e).get
      require(e == e_2)

      val iden = (e * e_inv).get
      require(iden.isIdentity)
    }
  }

  test("any group element should support operations with Try[GroupElement] arguments") {
    forAll(dlogGroups) { implicit group =>
      val e1 = group.createRandomGroupElement.get
      val e2Try = group.createRandomGroupElement

      val e1e2Try = e1 * e2Try
      val e1Try = e1e2Try.get / e2Try

      require(e1Try.get == e1)
    }
  }
}
