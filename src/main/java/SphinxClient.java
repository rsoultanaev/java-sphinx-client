import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.io.IOException;
import java.math.BigInteger;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class SphinxClient {
    public static final String RELAY_FLAG = new String(new char[]{(char) 0xf0});
    public static final String DEST_FLAG = new String(new char[]{(char) 0xf1});
    public static final String SURB_FLAG = new String(new char[]{(char) 0xf2});

    public static byte[] encodeNode(int idnum) throws IOException {
        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        packer.packArrayHeader(2);
        packer.packString(RELAY_FLAG);
        packer.packInt(idnum);
        packer.close();

        return packer.toByteArray();
    }

    public static int[] randSubset(int[] lst, int nu) {
        if (lst.length < nu) {
            throw new SphinxException("Number of possible elements (" + lst.length + ") was less than the requested number (" + nu + ")");
        }

        SecureRandom secureRandom = new SecureRandom();

        long[] randoms = new long[lst.length];
        for (int i = 0; i < randoms.length; i++) {
            byte[] rand = new byte[8];
            secureRandom.nextBytes(rand);
            randoms[i] = (new BigInteger(1, rand)).longValue();
        }

        HashMap<Long, Integer> randToIndex = new HashMap<Long, Integer>();
        for (int i = 0; i < randoms.length; i++) {
            randToIndex.put(randoms[i], i);
        }

        Arrays.sort(randoms);

        int[] result = new int[nu];
        for (int i = 0; i < nu; i++) {
            result[i] = lst[randToIndex.get(randoms[i])];
        }

        return result;
    }

    public static HeaderAndSecrets createHeader(SphinxParams params, byte[][] nodelist, ECPoint[] keys, byte[] dest) {
        byte[][] nodeMeta = new byte[nodelist.length][];
        for (int i = 0; i < nodelist.length; i++) {
            byte[] node = nodelist[i];
            byte[] nodeLength = {(byte) node.length};
            nodeMeta[i] = Util.concatByteArrays(nodeLength, node);
        }

        int nu = nodelist.length;
        ECCGroup group = params.getGroup();

        BigInteger blindFactor = group.genSecret();
        List<HeaderRecord> asbtuples = new ArrayList<HeaderRecord>();

        for (ECPoint k : keys) {
            ECPoint alpha = group.expon(group.getGenerator(), blindFactor);
            ECPoint s = group.expon(k, blindFactor);
            byte[] aesS = params.getAesKey(s);

            BigInteger b = params.hb(alpha, aesS);
            blindFactor = blindFactor.multiply(b);
            blindFactor = blindFactor.mod(group.getOrder());

            HeaderRecord headerRecord = new HeaderRecord(alpha, s, b, aesS);

            asbtuples.add(headerRecord);
        }

        byte[] phi = {};
        int minLen = params.getHeaderLength() - 32;

        for (int i = 1; i < nu; i++) {
            byte[] zeroes1 = new byte[params.getKeyLength() + nodeMeta[i].length];
            Arrays.fill(zeroes1, (byte) 0x00);
            byte[] plain = Util.concatByteArrays(phi, zeroes1);

            byte[] zeroes2 = new byte[minLen];
            Arrays.fill(zeroes2, (byte) 0x00);
            byte[] zeroes2plain = Util.concatByteArrays(zeroes2, plain);
            phi = params.xorRho(params.hrho(asbtuples.get(i-1).aes), zeroes2plain);
            phi = Arrays.copyOfRange(phi, minLen, phi.length);

            minLen -= nodeMeta[i].length + params.getKeyLength();
        }

        int lenMeta = 0;
        for (int i = 1; i < nodeMeta.length; i++) {
            lenMeta += nodeMeta[i].length;
        }

        if (phi.length != lenMeta + (nu-1)*params.getKeyLength()) {
            throw new SphinxException("Length of phi (" + phi.length + ") did not match the expected length (" + (lenMeta + (nu-1)*params.getKeyLength()) + ")");
        }

        byte[] destLength = {(byte) dest.length};
        byte[] finalRouting = Util.concatByteArrays(destLength, dest);

        int randomPadLen = (params.getHeaderLength() - 32) - lenMeta - (nu-1)*params.getKeyLength() - finalRouting.length;
        if (randomPadLen < 0) {
            throw new SphinxException("Length of random pad (" + randomPadLen + ") must be non-negative");
        }

        SecureRandom secureRandom = new SecureRandom();
        byte[] randomPad = new byte[randomPadLen];
        secureRandom.nextBytes(randomPad);

        byte[] beta = Util.concatByteArrays(finalRouting, randomPad);
        beta = params.xorRho(params.hrho(asbtuples.get(nu - 1).aes), beta);
        beta = Util.concatByteArrays(beta, phi);

        byte[] gamma = params.mu(params.hmu(asbtuples.get(nu-1).aes), beta);

        for (int i = nu - 2; i >= 0; i--) {
            byte[] nodeId = nodeMeta[i+1];

            int plainBetaLen = (params.getHeaderLength() - 32) - params.getKeyLength() - nodeId.length;
            byte[] plainBeta = Arrays.copyOf(beta, plainBetaLen);
            byte[] plain = Util.concatByteArrays(nodeId, gamma, plainBeta);

            beta = params.xorRho(params.hrho(asbtuples.get(i).aes), plain);
            gamma = params.mu(params.hmu(asbtuples.get(i).aes), beta);
        }

        Header header = new Header(asbtuples.get(0).alpha, beta, gamma);

        byte[][] secrets = new byte[asbtuples.size()][];
        for (int i = 0; i < asbtuples.size(); i++) {
            secrets[i] = asbtuples.get(i).aes;
        }

        return new HeaderAndSecrets(header, secrets);
    }

    public static HeaderAndDelta createForwardMessage(SphinxParams params, byte[][] nodelist, ECPoint[] keys, DestinationAndMessage destinationAndMessage) throws IOException {
        MessageBufferPacker packer;

        packer = MessagePack.newDefaultBufferPacker();
        packer.packArrayHeader(1);
        packer.packString(DEST_FLAG);
        packer.close();

        byte[] finalDestination = packer.toByteArray();
        HeaderAndSecrets headerAndSecrets = createHeader(params, nodelist, keys, finalDestination);

        packer = MessagePack.newDefaultBufferPacker();
        packer.packArrayHeader(2);
        packer.packBinaryHeader(destinationAndMessage.destination.length);
        packer.writePayload(destinationAndMessage.destination);
        packer.packBinaryHeader(destinationAndMessage.message.length);
        packer.writePayload(destinationAndMessage.message);
        packer.close();

        byte[] encodedDestAndMsg = packer.toByteArray();

        byte[] zeroes = new byte[params.getKeyLength()];
        Arrays.fill(zeroes, (byte) 0x00);

        byte[] body = Util.concatByteArrays(zeroes, encodedDestAndMsg);
        body = padBody(params.getBodyLength(), body);

        byte[][] secrets = headerAndSecrets.secrets;
        byte[] delta = params.pi(params.hpi(secrets[nodelist.length - 1]), body);

        for (int i = nodelist.length - 2; i >= 0; i--) {
            delta = params.pi(params.hpi(secrets[i]), delta);
        }

        return new HeaderAndDelta(headerAndSecrets.header, delta);
    }

    public static Surb createSurb(SphinxParams params, byte[][] nodelist, ECPoint[] keys, byte[] dest) throws IOException {
        SecureRandom secureRandom = new SecureRandom();
        int nu = nodelist.length;

        byte[] xid = new byte[params.getKeyLength()];
        secureRandom.nextBytes(xid);

        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        packer.packArrayHeader(3);
        packer.packString(SURB_FLAG);
        packer.packBinaryHeader(dest.length);
        packer.writePayload(dest);
        packer.packBinaryHeader(xid.length);
        packer.writePayload(xid);
        packer.close();

        byte[] finalDest = packer.toByteArray();
        HeaderAndSecrets headerAndSecrets = createHeader(params, nodelist, keys, finalDest);

        byte[] ktilde = new byte[params.getKeyLength()];
        secureRandom.nextBytes(ktilde);

        byte[][] hashedSecrets = new byte[headerAndSecrets.secrets.length][];
        for (int i = 0; i < hashedSecrets.length; i++) {
            hashedSecrets[i] = params.hpi(headerAndSecrets.secrets[i]);
        }

        byte[][] keytuple = new byte[hashedSecrets.length + 1][];
        keytuple[0] = ktilde;

        for (int i = 1; i < keytuple.length; i++) {
            keytuple[i] = hashedSecrets[i - 1];
        }

        NymTuple nymTuple = new NymTuple(nodelist[0], headerAndSecrets.header, ktilde);

        return new Surb(xid, keytuple, nymTuple);
    }

    public static HeaderAndDelta packageSurb(SphinxParams params, NymTuple nymTuple, byte[] message) {
        byte[] zeroes = new byte[params.getKeyLength()];
        Arrays.fill(zeroes, (byte) 0x00);
        byte[] zeroPaddedMessage = Util.concatByteArrays(zeroes, message);
        byte[] body = padBody(params.getBodyLength(), zeroPaddedMessage);
        byte[] delta = params.pi(nymTuple.ktilde, body);

        return new HeaderAndDelta(nymTuple.header, delta);
    }

    public static DestinationAndMessage receiveForward(SphinxParams params, byte[] delta) throws IOException {
        byte[] zeroes = new byte[params.getKeyLength()];
        Arrays.fill(zeroes, (byte) 0x00);

        if (!Arrays.equals(Arrays.copyOf(delta, params.getKeyLength()), zeroes)) {
            String deltaPrefix = Hex.toHexString(Arrays.copyOf(delta, params.getKeyLength()));
            String expectedPrefix = Hex.toHexString(zeroes);
            throw new SphinxException("Prefix of delta (" + deltaPrefix + ") did not match the expected prefix (" + expectedPrefix + ")");
        }

        byte[] encodedDestAndMsg = unpadBody(Arrays.copyOfRange(delta, params.getKeyLength(), delta.length));
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(encodedDestAndMsg);
        unpacker.unpackArrayHeader();
        int destLength = unpacker.unpackBinaryHeader();
        byte[] destination = unpacker.readPayload(destLength);
        int msgLength = unpacker.unpackBinaryHeader();
        byte[] message = unpacker.readPayload(msgLength);
        unpacker.close();

        return new DestinationAndMessage(destination, message);
    }

    public static byte[] receiveSurb(SphinxParams params, byte[][] keytuple, byte[] delta) {
        byte[] ktilde = keytuple[0];
        for (int i = keytuple.length - 1; i > 0; i--) {
            delta = params.pi(keytuple[i], delta);
        }
        delta = params.pii(ktilde, delta);

        byte[] zeroes = new byte[params.getKeyLength()];
        Arrays.fill(zeroes, (byte) 0x00);

        if (!Arrays.equals(Arrays.copyOf(delta, params.getKeyLength()), zeroes)) {
            String deltaPrefix = Hex.toHexString(Arrays.copyOf(delta, params.getKeyLength()));
            String expectedPrefix = Hex.toHexString(zeroes);
            throw new SphinxException("Prefix of delta (" + deltaPrefix + ") did not match the expected prefix (" + expectedPrefix + ")");
        }

        return unpadBody(Arrays.copyOfRange(delta, params.getKeyLength(), delta.length));
    }

    public static byte[] packMessage(SphinxPacket sphinxPacket) throws IOException {
        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();

        int headerLength = sphinxPacket.paramLengths.headerLength;
        int bodyLength = sphinxPacket.paramLengths.bodyLength;

        Header header = sphinxPacket.headerAndDelta.header;
        byte[] delta = sphinxPacket.headerAndDelta.delta;
        byte[] packedEcPoint = packECPoint(header.alpha);

        packer
                .packArrayHeader(2)
                .packArrayHeader(2)
                .packInt(headerLength)
                .packInt(bodyLength)
                .packArrayHeader(2)
                .packArrayHeader(3)
                .packExtensionTypeHeader((byte) 2, packedEcPoint.length)
                .writePayload(packedEcPoint)
                .packBinaryHeader(header.beta.length)
                .writePayload(header.beta)
                .packBinaryHeader(header.gamma.length)
                .writePayload(header.gamma)
                .packBinaryHeader(delta.length)
                .writePayload(delta);
        packer.close();

        return packer.toByteArray();
    }

    public static SphinxPacket unpackMessage(byte[] m) throws IOException {
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(m);
        unpacker.unpackArrayHeader();
        unpacker.unpackArrayHeader();
        int headerLength = unpacker.unpackInt();
        int bodyLength = unpacker.unpackInt();
        unpacker.unpackArrayHeader();
        unpacker.unpackArrayHeader();
        int alphaLength = unpacker.unpackExtensionTypeHeader().getLength();
        byte[] packedAlpha = unpacker.readPayload(alphaLength);
        int betaLength = unpacker.unpackBinaryHeader();
        byte[] beta = unpacker.readPayload(betaLength);
        int gammaLength = unpacker.unpackBinaryHeader();
        byte[] gamma = unpacker.readPayload(gammaLength);
        int deltaLength = unpacker.unpackBinaryHeader();
        byte[] delta = unpacker.readPayload(deltaLength);
        unpacker.close();

        unpacker = MessagePack.newDefaultUnpacker(packedAlpha);
        unpacker.unpackArrayHeader();
        unpacker.unpackInt();
        int encodedAlphaLength = unpacker.unpackBinaryHeader();
        byte[] encodedAlpha = unpacker.readPayload(encodedAlphaLength);
        unpacker.close();

        ECPoint alpha = Util.decodeECPoint(encodedAlpha);

        ParamLengths paramLengths = new ParamLengths(headerLength, bodyLength);
        Header header = new Header(alpha, beta, gamma);

        HeaderAndDelta headerAndDelta = new HeaderAndDelta(header, delta);

        return new SphinxPacket(paramLengths, headerAndDelta);
    }

    private static byte[] padBody(int msgtotalsize, byte[] body) {
        byte[] padByte = {(byte) 0x7f};
        byte[] effs = new byte[msgtotalsize - (body.length + 1)];
        Arrays.fill(effs, (byte) 0xff);

        return Util.concatByteArrays(body, padByte, effs);
    }

    private static byte[] unpadBody(byte[] body) {
        int l = body.length - 1;
        byte xMarker = (byte) 0x7f;
        byte fMarker = (byte) 0xff;

        while (body[l] == fMarker && l > 0) {
            l--;
        }

        byte[] ret = {};

        if (body[l] == xMarker) {
            ret = Arrays.copyOf(body, l);
        }

        return ret;
    }

    private static byte[] packECPoint(ECPoint ecPoint) throws IOException {
        byte[] encodedEcPoint = ecPoint.getEncoded(true);

        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        packer.packArrayHeader(2);
        packer.packInt(ECCGroup.DEFAULT_CURVE_NID);
        packer.packBinaryHeader(encodedEcPoint.length);
        packer.writePayload(encodedEcPoint);
        packer.close();

        return packer.toByteArray();
    }
}
