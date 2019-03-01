package treasury.crypto.native

import java.nio.ByteBuffer

import jnr.ffi.{Pointer, Runtime}
import org.scalatest.FunSuite
import treasury.crypto.core.primitives.dlog.openssl.ECDiscreteLogGroupOpenSSL

class LibLoaderTest extends FunSuite {

  test("Load OpenSSL library") {
    val openSSl = NativeLibraryLoader.openSslAPI.get

    val array = BigInt(234234).toByteArray
    val outArr = new Array[Byte](3)
    //val buffer = ByteBuffer.allocate(64)
    //val pointer: Pointer = Pointer.wrap(Runtime.getRuntime(openSSl), buffer)

    val p = openSSl.BN_bin2bn(array, array.length, null)


    val len = openSSl.BN_bn2bin(p, outArr)
    val outInt = BigInt(outArr)

    openSSl.BN_free(p)


    require(true)
  }

  test("create curve") {
    val dlogOpenSSL = ECDiscreteLogGroupOpenSSL("secp256k1")
    require(dlogOpenSSL.isSuccess)
  }

}
