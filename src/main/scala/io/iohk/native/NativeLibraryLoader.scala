package io.iohk.native

import jnr.ffi.LibraryLoader

import scala.util.Try

object NativeLibraryLoader {

  lazy val openSslAPI = loadFromResource("/libcrypto.so.1.1", classOf[OpenSslAPI])

  private def loadFromResource[T](libName: String, cl: Class[T]): Try[T] = Try {
    val resourcePath = getClass.getResource(libName).getPath
    LibraryLoader.create(cl).load(resourcePath)
  }
}
