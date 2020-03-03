package io.iohk.core.crypto.primitives.dlog

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups.AvailableGroups
import io.iohk.core.crypto.primitives.dlog.bouncycastle.ECDiscreteLogGroupBc
import io.iohk.core.crypto.primitives.dlog.openssl.ECDiscreteLogGroupOpenSSL

import scala.util.Try

object DiscreteLogGroupFactory {

    object AvailableGroups extends Enumeration {
      type AvailableGroups = Value
      val BC_secp256k1 = Value("BC_secp256k1")
      val BC_secp256r1 = Value("BC_secp256r1")
      val OpenSSL_secp256k1 = Value("OpenSSL_secp256k1")
      val OpenSSL_secp256r1 = Value("OpenSSL_secp256r1")

      def getEllipticCurveGroups: Seq[Value] = this.values.toSeq // currently all supported groups are EC groups
    }

    def constructDlogGroup(group: AvailableGroups): Try[DiscreteLogGroup] = {
      group match {
        case AvailableGroups.BC_secp256k1 => ECDiscreteLogGroupBc.apply("secp256k1")
        case AvailableGroups.BC_secp256r1 => ECDiscreteLogGroupBc.apply("secp256r1")
        case AvailableGroups.OpenSSL_secp256k1 => ECDiscreteLogGroupOpenSSL.apply(ECDiscreteLogGroupOpenSSL.AvailableCurves.secp256k1)
        case AvailableGroups.OpenSSL_secp256r1 => ECDiscreteLogGroupOpenSSL.apply(ECDiscreteLogGroupOpenSSL.AvailableCurves.secp256r1)
        case _ => Try(throw new IllegalArgumentException(s"Group $group is not supported"))
      }
    }
}
