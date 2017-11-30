import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

public class SphinxParams {

    public String aesCtr(String message, String iv, String key) {
        CipherParameters params = new ParametersWithIV(new KeyParameter(Hex.decode(key)), Hex.decode(iv));
        SICBlockCipher engine = new SICBlockCipher(new AESEngine());

        engine.init(true, params);

        byte[] cipher = new byte[5 * 16];
        byte[] plain = Hex.decode(message);

        engine.processBytes(plain, 0, plain.length, cipher, 0);

        return Hex.toHexString(cipher);
    }

    public String hash(String input) {
        SHA256Digest digest = new SHA256Digest();
        byte[] inputBytes = Hex.decode(input);
        byte[] output = new byte[digest.getDigestSize()];
        digest.update(inputBytes, 0, inputBytes.length);
        digest.doFinal(output, 0);
        return Hex.toHexString(output);
    }
}
