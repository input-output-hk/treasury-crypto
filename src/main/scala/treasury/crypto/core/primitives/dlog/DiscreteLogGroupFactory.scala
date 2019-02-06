package treasury.crypto.core.primitives.dlog

import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups.AvailableGroups
import treasury.crypto.core.primitives.dlog.bouncycastle.ECDiscreteLogGroupBc

import scala.util.Try

object DiscreteLogGroupFactory {

    object AvailableGroups extends Enumeration {
      type AvailableGroups = Value
      val BC_secp256k1, BC_secp256r1 = Value
    }

    def constructDlogGroup(group: AvailableGroups): Try[DiscreteLogGroup] = {
      group match {
        case AvailableGroups.BC_secp256k1 => ECDiscreteLogGroupBc.apply("secp256k1")
        case _ => Try(throw new IllegalArgumentException(s"Group $group is not supported"))
      }
    }
}
