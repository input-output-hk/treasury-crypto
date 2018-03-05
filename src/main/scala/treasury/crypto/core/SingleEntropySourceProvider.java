package treasury.crypto.core;

import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;

// Fragment taken from here:
// http://book2s.com/java/src/package/org/cryptoworkshop/ximix/common/util/challenge/seededchallenger.html

class SingleEntropySourceProvider implements
        EntropySourceProvider {
    private final byte[] data;

    protected SingleEntropySourceProvider(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException(
                    "No challenge seed available to seeded challenger.");
        }

        this.data = data;
    }

    public EntropySource get(final int bitsRequired) {
        return new EntropySource() {
            int index = 0;

            public boolean isPredictionResistant() {
                return true;
            }

            public byte[] getEntropy() {
                byte[] rv = new byte[bitsRequired / 8];

                if (data.length < (index + rv.length)) {
                    throw new IllegalStateException(
                            "Insufficient entropy - need " + rv.length
                                    + " bytes for challenge seed.");
                }

                System.arraycopy(data, index, rv, 0, rv.length);

                index += bitsRequired / 8;

                return rv;
            }

            public int entropySize() {
                return bitsRequired;
            }
        };
    }
}