package treasury.crypto.native

import java.nio.ByteBuffer

import jnr.ffi.{Pointer, Runtime}
import org.scalatest.FunSuite
import treasury.crypto.core.primitives.dlog.openssl.ECDiscreteLogGroupOpenSSL

class LibLoaderTest extends FunSuite {

  test("Load OpenSSL library") {
    val openSSl = NativeLibraryLoader.openSslAPI.get
    val bnCtx = openSSl.BN_CTX_new

    val three = BigInt(3).toByteArray
    val two = BigInt(2).toByteArray

    val outArrMinOne = new Array[Byte](3)

    val three_ptr = openSSl.BN_bin2bn(three, three.length, null)
    val two_ptr = openSSl.BN_bin2bn(two, two.length, null)
    openSSl.BN_set_negative(two_ptr, 1)

    val rr = openSSl.BN_nnmod(two_ptr, two_ptr, three_ptr, bnCtx)

    val len = openSSl.BN_bn2bin(two_ptr, outArrMinOne)
    val outInt = BigInt(outArrMinOne)


    require(true)
  }

  test("create curve") {
    val dlogOpenSSL = ECDiscreteLogGroupOpenSSL("secp256k1")
    require(dlogOpenSSL.isSuccess)
  }

}
