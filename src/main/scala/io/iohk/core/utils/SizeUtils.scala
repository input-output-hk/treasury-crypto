package io.iohk.core.utils

trait HasSize {
  def size: Int
}

object SizeUtils {

  def getSize[T <: HasSize](vector: Seq[T]): Int = {
    val maxSize = vector.maxBy(_.size).size
    val totalSize = vector.foldLeft(0){(totalSize, currentElement) => totalSize + currentElement.size}

    println(maxSize + " B;\t" + totalSize + " B")

    totalSize
  }
}
