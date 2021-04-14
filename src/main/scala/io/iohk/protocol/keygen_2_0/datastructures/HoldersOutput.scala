package io.iohk.protocol.keygen_2_0.datastructures

import io.iohk.protocol.keygen_2_0.NIZKs.rnce.{CorrectSharesDecryption, CorrectSharesEncryption}
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.RncePublicKeyLight

case class OutputDKG(
                      sk1_shares:    Seq[SecretShare], // shares of the first partial secret key
                      sk2_shares:    Seq[SecretShare], // shares of the second partial secret key
                      pubKeyPartial: RncePublicKeyLight, // partial public key: g1^sk1 * g2^sk2
                      proofEnc:      Option[CorrectSharesEncryption.Proof] // NIZK-proof of correctness of encrypted shares
                    )

case class OutputMaintenance(
                              s1_shares: Seq[SecretShare], // shares of the first secret share
                              s2_shares: Seq[SecretShare], // shares of the second secret share
                              proofDec:  Option[CorrectSharesDecryption.Proof], // NIZK-proof of correctness of decrypted shares that were received
                              proofEnc:  Option[CorrectSharesEncryption.Proof] // NIZK-proof of correctness of encrypted shares that were posted
                            )

case class HoldersOutput(dkg:         Option[OutputDKG],
                         maintenance: Option[OutputMaintenance])
