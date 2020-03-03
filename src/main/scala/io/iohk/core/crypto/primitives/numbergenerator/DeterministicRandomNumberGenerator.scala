package io.iohk.core.crypto.primitives.numbergenerator

/*
* Deterministic random number generators is a type of RNG which produces a sequence of numbers whose properties approximate
* the properties of a sequence of random numbers, but it is completely defined by the initial seed value.
*/
abstract class DeterministicRandomNumberGenerator(val seed: Array[Byte]) extends RandomNumberGenerator
