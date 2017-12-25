import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

import java.util.Arrays;

public class SphinxParams {

    private final int keyLength;
    private final int bodyLength;
    private final int headerLength;
    private final ECCGroup group;

    public SphinxParams() {
        this.keyLength = 16;
        this.bodyLength = 1024;
        this.headerLength = 192;
        this.group = new ECCGroup();
    }

    public int getKeyLength() {
        return keyLength;
    }

    public int getBodyLength() {
        return bodyLength;
    }

    public int getHeaderLength() {
        return headerLength;
    }

    public ECCGroup getGroup() {
        return group;
    }

    public byte[] aesCtr(byte[] key, byte[] message, byte[] iv) {
        CipherParameters params = new ParametersWithIV(new KeyParameter(key), iv);
        SICBlockCipher engine = new SICBlockCipher(new AESEngine());

        engine.init(true, params);

        byte[] ciphertext = new byte[message.length];

        engine.processBytes(message, 0, message.length, ciphertext, 0);

        return ciphertext;
    }

    public byte[] aesCtr(byte[] key, byte[] message) {
        byte[] iv = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        return aesCtr(key, message, iv);
    }

    public byte[] lionessEnc(byte[] key, byte[] message) {
        assert(key.length == keyLength);
        assert(message.length >= keyLength * 2);

        // Round 1
        byte[] messageShort = Arrays.copyOf(message, keyLength);
        byte[] messageLong = Arrays.copyOfRange(message, keyLength, message.length);
        byte[] one = "1".getBytes();
        byte[] k1 = Arrays.copyOf(hash(Util.concatByteArrays(messageLong, key, one)), keyLength);
        byte[] c = aesCtr(key, messageShort, k1);
        byte[] r1 = Util.concatByteArrays(c, messageLong);

        // Round 2
        byte[] r1Short = Arrays.copyOf(r1, keyLength);
        byte[] r1Long = Arrays.copyOfRange(r1, keyLength, message.length);
        c = aesCtr(key, r1Long, r1Short);
        byte[] r2 = Util.concatByteArrays(r1Short, c);

        // Round 3
        byte[] r2Short = Arrays.copyOf(r2, keyLength);
        byte[] r2Long = Arrays.copyOfRange(r2, keyLength, message.length);
        byte[] three = "3".getBytes();
        byte[] k3 = Arrays.copyOf(hash(Util.concatByteArrays(r2Long, key, three)), keyLength);
        c = aesCtr(key, r2Short, k3);
        byte[] r3 = Util.concatByteArrays(c, r2Long);

        // Round 4
        byte[] r3Short = Arrays.copyOf(r3, keyLength);
        byte[] r3Long = Arrays.copyOfRange(r3, keyLength, message.length);
        c = aesCtr(key, r3Long, r3Short);
        byte[] r4 = Util.concatByteArrays(r3Short, c);

        return r4;
    }

    public byte[] lionessDec(byte[] key, byte[] message) {
        assert(key.length == keyLength);
        assert(message.length >= keyLength * 2);

        byte[] r4Short = Arrays.copyOf(message, keyLength);
        byte[] r4Long = Arrays.copyOfRange(message, keyLength, message.length);

        // Round 4
        byte[] r3Long = aesCtr(key, r4Long, r4Short);
        byte[] r3Short = r4Short;

        // Round 3
        byte[] three = "3".getBytes();
        byte[] k2 = Arrays.copyOf(hash(Util.concatByteArrays(r3Long, key, three)), keyLength);
        byte[] r2Short = aesCtr(key, r3Short, k2);
        byte[] r2Long = r3Long;

        // Round 2
        byte[] r1Long = aesCtr(key, r2Long, r2Short);
        byte[] r1Short = r2Short;

        // Round 1
        byte[] one = "1".getBytes();
        byte[] k0 = Arrays.copyOf(hash(Util.concatByteArrays(r1Long, key, one)), keyLength);
        byte[] c = aesCtr(key, r1Short, k0);
        byte[] r0 = Util.concatByteArrays(c, r1Long);

        return r0;
    }

    public byte[] xorRho(byte[] key, byte[] plain) {
        assert (key.length == keyLength);

        return aesCtr(key, plain);
    }

    public byte[] mu(byte[] key, byte[] data) {
        Mac mac = new HMac(new SHA256Digest());
        CipherParameters cipherParameters = new KeyParameter(key);
        mac.init(cipherParameters);
        byte[] output = new byte[mac.getMacSize()];

        mac.update(data, 0, data.length);
        mac.doFinal(output, 0);

        return Arrays.copyOf(output, keyLength);
    }

    public byte[] pi(byte[] key, byte[] data) {
        assert(key.length == keyLength);
        assert(data.length == bodyLength);

        return lionessEnc(key, data);
    }

    public byte[] pii(byte[] key, byte[] data) {
        assert(key.length == keyLength);
        assert(data.length == bodyLength);

        return lionessDec(key, data);
    }

    public byte[] hash(byte[] data) {
        SHA256Digest digest = new SHA256Digest();
        byte[] output = new byte[digest.getDigestSize()];

        digest.update(data, 0, data.length);
        digest.doFinal(output, 0);

        return output;
    }

    public byte[] getAesKey(ECPoint s) {
        byte[] prefix = "aes_key:".getBytes();
        byte[] printable = group.printable(s);

        byte[] data = Util.concatByteArrays(prefix, printable);
        byte[] hash = hash(data);

        return Arrays.copyOf(hash, keyLength);
    }

    public byte[] deriveKey(byte[] k, byte[] flavor) {
        byte[] m = new byte[keyLength];

        return aesCtr(k, m, flavor);
    }

    public BigInteger hb(ECPoint alpha, byte[] k) {
        byte[] flavor = "hbhbhbhbhbhbhbhb".getBytes();
        byte[] K = deriveKey(k, flavor);

        return group.makeexp(K);
    }

    public byte[] hrho(byte[] k) {
        byte[] flavor = "hrhohrhohrhohrho".getBytes();

        return deriveKey(k, flavor);
    }

    public byte[] hmu(byte[] k) {
        byte[] flavor = "hmu:hmu:hmu:hmu:".getBytes();

        return deriveKey(k, flavor);
    }

    public byte[] hpi(byte[] k) {
        byte[] flavor = "hpi:hpi:hpi:hpi:".getBytes();

        return deriveKey(k, flavor);
    }

    public byte[] htau(byte[] k) {
        byte[] flavor = "htauhtauhtauhtau".getBytes();

        return deriveKey(k, flavor);
    }
}
