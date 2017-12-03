import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class SphinxParams {

    public byte[] aesCtr(byte[] key, byte[] message, byte[] iv) {
        CipherParameters params = new ParametersWithIV(new KeyParameter(key), iv);
        SICBlockCipher engine = new SICBlockCipher(new AESEngine());

        engine.init(true, params);

        byte[] ciphertext = new byte[message.length];

        engine.processBytes(message, 0, message.length, ciphertext, 0);

        return ciphertext;
    }

    public byte[] lionessEnc(byte[] key, byte[] message) {
        return null;
    }

    public byte[] lionessDec(byte[] key, byte[] message) {
        return null;
    }

    public byte[] xorRho(byte[] key, byte[] plain) {
        return null;
    }

    public byte[] mu(byte[] key, byte[] data) {
        return null;
    }

    public byte[] pi(byte[] key, byte[] data) {
        return null;
    }

    public byte[] pii(byte[] key, byte[] data) {
        return null;
    }

    public byte[] hash(byte[] data) {
        SHA256Digest digest = new SHA256Digest();
        byte[] output = new byte[digest.getDigestSize()];

        digest.update(data, 0, data.length);
        digest.doFinal(output, 0);

        return output;
    }

    public byte[] getAesKey(byte[] s) {
        return null;
    }

    public byte[] deriveKey(byte[] k, byte[] flavor) {
        return null;
    }

    public byte[] hb(byte[] alpha, byte[] k) {
        return null;
    }

    public byte[] hrho(byte[] k) {
        return null;
    }

    public byte[] hmu(byte[] k) {
        return null;
    }

    public byte[] hpi(byte[] k) {
        return null;
    }

    public byte[] htau(byte[] k) {
        return null;
    }
}
