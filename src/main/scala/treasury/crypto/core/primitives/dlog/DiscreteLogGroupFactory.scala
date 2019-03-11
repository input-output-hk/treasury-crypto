package treasury.crypto.core.primitives.dlog

import treasury.crypto.core.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups.AvailableGroups
import treasury.crypto.core.primitives.dlog.bouncycastle.ECDiscreteLogGroupBc
import treasury.crypto.core.primitives.dlog.openssl.ECDiscreteLogGroupOpenSSL

import scala.util.Try

object DiscreteLogGroupFactory {

    object AvailableGroups extends Enumeration {
      type AvailableGroups = String
      val BC_secp256k1 = "BC_secp256k1"
      val OpenSSL_secp256k1 = "OpenSSL_secp256k1"
      val OpenSSL_secp256r1 = "OpenSSL_secp256r1"
    }

    def constructDlogGroup(group: AvailableGroups): Try[DiscreteLogGroup] = {
      group match {
        case AvailableGroups.BC_secp256k1 => ECDiscreteLogGroupBc.apply("secp256k1")
        case AvailableGroups.OpenSSL_secp256k1 => ECDiscreteLogGroupOpenSSL.apply(ECDiscreteLogGroupOpenSSL.AvailableCurves.secp256k1)
        case AvailableGroups.OpenSSL_secp256r1 => ECDiscreteLogGroupOpenSSL.apply(ECDiscreteLogGroupOpenSSL.AvailableCurves.secp256r1)
        case _ => Try(throw new IllegalArgumentException(s"Group $group is not supported"))
      }
    }
}
