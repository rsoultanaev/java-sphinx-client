package com.robertsoultanaev.javasphinx;

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

import static com.robertsoultanaev.javasphinx.Util.concatenate;
import static com.robertsoultanaev.javasphinx.Util.slice;

public class SphinxClient {
    public static final String RELAY_FLAG = new String(new char[]{(char) 0xf0});
    public static final String DEST_FLAG = new String(new char[]{(char) 0xf1});
    public static final String SURB_FLAG = new String(new char[]{(char) 0xf2});

    public static final int MAX_DEST_SIZE = 127;

    public static byte[] encodeNode(int idnum) {
        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();

        try {
            packer.packArrayHeader(2);
            packer.packString(RELAY_FLAG);
            packer.packInt(idnum);
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to encode node");
        }

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
            nodeMeta[i] = concatenate(nodeLength, node);
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
            byte[] plain = concatenate(phi, zeroes1);

            byte[] zeroes2 = new byte[minLen];
            Arrays.fill(zeroes2, (byte) 0x00);
            byte[] zeroes2plain = concatenate(zeroes2, plain);
            phi = params.xorRho(params.hrho(asbtuples.get(i-1).aes), zeroes2plain);
            phi = slice(phi, minLen, phi.length);

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
        byte[] finalRouting = concatenate(destLength, dest);

        int randomPadLen = (params.getHeaderLength() - 32) - lenMeta - (nu-1)*params.getKeyLength() - finalRouting.length;
        if (randomPadLen < 0) {
            throw new SphinxException("Length of random pad (" + randomPadLen + ") must be non-negative");
        }

        SecureRandom secureRandom = new SecureRandom();
        byte[] randomPad = new byte[randomPadLen];
        secureRandom.nextBytes(randomPad);

        byte[] beta = concatenate(finalRouting, randomPad);
        beta = params.xorRho(params.hrho(asbtuples.get(nu - 1).aes), beta);
        beta = concatenate(beta, phi);

        byte[] gamma = params.mu(params.hmu(asbtuples.get(nu-1).aes), beta);

        for (int i = nu - 2; i >= 0; i--) {
            byte[] nodeId = nodeMeta[i+1];

            int plainBetaLen = (params.getHeaderLength() - 32) - params.getKeyLength() - nodeId.length;
            byte[] plainBeta = slice(beta, plainBetaLen);
            byte[] plain = concatenate(nodeId, gamma, plainBeta);

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

    public static HeaderAndDelta createForwardMessage(SphinxParams params, byte[][] nodelist, ECPoint[] keys, DestinationAndMessage destinationAndMessage) {
        byte[] dest = destinationAndMessage.destination;
        byte[] message = destinationAndMessage.message;

        if (!(dest.length > 0 && dest.length < MAX_DEST_SIZE)) {
            throw new SphinxException("Destination has to be between 1 and " + MAX_DEST_SIZE + " bytes long");
        }

        MessageBufferPacker packer;

        packer = MessagePack.newDefaultBufferPacker();
        try {
            packer.packArrayHeader(1);
            packer.packString(DEST_FLAG);
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to pack the destination flag");
        }

        byte[] finalDestination = packer.toByteArray();
        HeaderAndSecrets headerAndSecrets = createHeader(params, nodelist, keys, finalDestination);

        packer = MessagePack.newDefaultBufferPacker();
        try {
            packer.packArrayHeader(2);
            packer.packBinaryHeader(dest.length);
            packer.writePayload(dest);
            packer.packBinaryHeader(message.length);
            packer.writePayload(message);
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to pack destination and message");
        }

        byte[] encodedDestAndMsg = packer.toByteArray();

        byte[] zeroes = new byte[params.getKeyLength()];
        Arrays.fill(zeroes, (byte) 0x00);

        byte[] body = concatenate(zeroes, encodedDestAndMsg);
        body = padBody(params.getBodyLength(), body);

        byte[][] secrets = headerAndSecrets.secrets;
        byte[] delta = params.pi(params.hpi(secrets[nodelist.length - 1]), body);

        for (int i = nodelist.length - 2; i >= 0; i--) {
            delta = params.pi(params.hpi(secrets[i]), delta);
        }

        return new HeaderAndDelta(headerAndSecrets.header, delta);
    }

    public static Surb createSurb(SphinxParams params, byte[][] nodelist, ECPoint[] keys, byte[] dest) {
        SecureRandom secureRandom = new SecureRandom();
        int nu = nodelist.length;

        byte[] xid = new byte[params.getKeyLength()];
        secureRandom.nextBytes(xid);

        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        try {
            packer.packArrayHeader(3);
            packer.packString(SURB_FLAG);
            packer.packBinaryHeader(dest.length);
            packer.writePayload(dest);
            packer.packBinaryHeader(xid.length);
            packer.writePayload(xid);
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to pack SURB");
        }

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
        byte[] zeroPaddedMessage = concatenate(zeroes, message);
        byte[] body = padBody(params.getBodyLength(), zeroPaddedMessage);
        byte[] delta = params.pi(nymTuple.ktilde, body);

        return new HeaderAndDelta(nymTuple.header, delta);
    }

    public static DestinationAndMessage receiveForward(SphinxParams params, byte[] delta) {
        byte[] zeroes = new byte[params.getKeyLength()];
        Arrays.fill(zeroes, (byte) 0x00);

        if (!Arrays.equals(slice(delta, params.getKeyLength()), zeroes)) {
            String deltaPrefix = Hex.toHexString(slice(delta, params.getKeyLength()));
            String expectedPrefix = Hex.toHexString(zeroes);
            throw new SphinxException("Prefix of delta (" + deltaPrefix + ") did not match the expected prefix (" + expectedPrefix + ")");
        }

        byte[] encodedDestAndMsg = unpadBody(slice(delta, params.getKeyLength(), delta.length));
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(encodedDestAndMsg);
        byte[] destination, message;
        try {
            unpacker.unpackArrayHeader();
            int destLength = unpacker.unpackBinaryHeader();
            destination = unpacker.readPayload(destLength);
            int msgLength = unpacker.unpackBinaryHeader();
            message = unpacker.readPayload(msgLength);
            unpacker.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to unpack the destination and message");
        }

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

        if (!Arrays.equals(slice(delta, params.getKeyLength()), zeroes)) {
            String deltaPrefix = Hex.toHexString(slice(delta, params.getKeyLength()));
            String expectedPrefix = Hex.toHexString(zeroes);
            throw new SphinxException("Prefix of delta (" + deltaPrefix + ") did not match the expected prefix (" + expectedPrefix + ")");
        }

        return unpadBody(slice(delta, params.getKeyLength(), delta.length));
    }

    public static byte[] packMessage(SphinxPacket sphinxPacket) {
        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();

        int headerLength = sphinxPacket.paramLengths.headerLength;
        int bodyLength = sphinxPacket.paramLengths.bodyLength;

        Header header = sphinxPacket.headerAndDelta.header;
        byte[] delta = sphinxPacket.headerAndDelta.delta;
        byte[] packedEcPoint = packECPoint(header.alpha);

        try {
            packer.packArrayHeader(2);
            packer.packArrayHeader(2);
            packer.packInt(headerLength);
            packer.packInt(bodyLength);
            packer.packArrayHeader(2);
            packer.packArrayHeader(3);
            packer.packExtensionTypeHeader((byte) 2, packedEcPoint.length);
            packer.writePayload(packedEcPoint);
            packer.packBinaryHeader(header.beta.length);
            packer.writePayload(header.beta);
            packer.packBinaryHeader(header.gamma.length);
            packer.writePayload(header.gamma);
            packer.packBinaryHeader(delta.length);
            packer.writePayload(delta);
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to pack the sphinx packet");
        }

        return packer.toByteArray();
    }

    public static SphinxPacket unpackMessage(byte[] m) {
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(m);
        int headerLength, bodyLength;
        byte[] packedAlpha, beta, gamma, delta;
        try {
            unpacker.unpackArrayHeader();
            unpacker.unpackArrayHeader();
            headerLength = unpacker.unpackInt();
            bodyLength = unpacker.unpackInt();
            unpacker.unpackArrayHeader();
            unpacker.unpackArrayHeader();
            int alphaLength = unpacker.unpackExtensionTypeHeader().getLength();
            packedAlpha = unpacker.readPayload(alphaLength);
            int betaLength = unpacker.unpackBinaryHeader();
            beta = unpacker.readPayload(betaLength);
            int gammaLength = unpacker.unpackBinaryHeader();
            gamma = unpacker.readPayload(gammaLength);
            int deltaLength = unpacker.unpackBinaryHeader();
            delta = unpacker.readPayload(deltaLength);
            unpacker.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to unpack the sphinx packet");
        }

        unpacker = MessagePack.newDefaultUnpacker(packedAlpha);
        byte[] encodedAlpha;
        try {
            unpacker.unpackArrayHeader();
            unpacker.unpackInt();
            int encodedAlphaLength = unpacker.unpackBinaryHeader();
            encodedAlpha = unpacker.readPayload(encodedAlphaLength);
            unpacker.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to unpack alpha");
        }

        ECPoint alpha = Util.decodeECPoint(encodedAlpha);

        ParamLengths paramLengths = new ParamLengths(headerLength, bodyLength);
        Header header = new Header(alpha, beta, gamma);

        HeaderAndDelta headerAndDelta = new HeaderAndDelta(header, delta);

        return new SphinxPacket(paramLengths, headerAndDelta);
    }

    public static int getMaxPayloadSize(SphinxParams params) {
        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        try {
            packer.packArrayHeader(2);
            packer.packBinaryHeader(MAX_DEST_SIZE);
            packer.packBinaryHeader(params.getBodyLength());
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to calculate the msgpack overhead");
        }

        int msgPackOverhead = packer.getBufferSize();

        // Added in padBody
        int padByteLength = 1;

        return params.getBodyLength() - params.getKeyLength() - padByteLength - msgPackOverhead;
    }

    private static byte[] padBody(int msgtotalsize, byte[] body) {
        byte[] initialPadByte = {(byte) 0x7f};
        int numPadBytes = msgtotalsize - (body.length + 1);

        if (numPadBytes < 0) {
            throw new SphinxException("Insufficient space for message");
        }

        byte[] padBytes = new byte[numPadBytes];
        Arrays.fill(padBytes, (byte) 0xff);

        return concatenate(body, initialPadByte, padBytes);
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
            ret = slice(body, l);
        }

        return ret;
    }

    private static byte[] packECPoint(ECPoint ecPoint) {
        byte[] encodedEcPoint = ecPoint.getEncoded(true);

        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        try {
            packer.packArrayHeader(2);
            packer.packInt(ECCGroup.DEFAULT_CURVE_NID);
            packer.packBinaryHeader(encodedEcPoint.length);
            packer.writePayload(encodedEcPoint);
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to pack the sphinx packet");
        }

        return packer.toByteArray();
    }
}
