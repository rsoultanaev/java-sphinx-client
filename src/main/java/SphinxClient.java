import org.bouncycastle.math.ec.ECPoint;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.io.IOException;
import java.math.BigInteger;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class SphinxClient {
    private final String RELAY_FLAG;
    private final String DEST_FLAG;
    private final String SURB_FLAG;

    public SphinxClient() {
        char[] relayFlagCharArr = {(char) 0xf0};
        RELAY_FLAG = new String(relayFlagCharArr);

        char[] destFlagCharArr = {(char) 0xf1};
        DEST_FLAG = new String(destFlagCharArr);

        char[] surbFlagCharArr = {(char) 0xf2};
        SURB_FLAG = new String(surbFlagCharArr);
    }

    byte[] padBody(SphinxParams params, int msgtotalsize, byte[] body) {
        byte[] padByte = {(byte) 0x7f};
        byte[] effs = new byte[msgtotalsize - (body.length + 1)];
        Arrays.fill(effs, (byte) 0xff);

        return params.concatByteArrays(body, padByte, effs);
    }

    byte[] unpadBody(byte[] body) {
        int l = body.length - 1;
        byte x_marker = (byte) 0x7f;
        byte f_marker = (byte) 0xff;

        while (body[l] == f_marker && l > 0) {
            l--;
        }

        byte[] ret = {};

        if (body[l] == x_marker) {
            ret = Arrays.copyOf(body, l);
        }

        return ret;
    }

    byte[] nodeEncoding(int idnum) {
        return null;
    }
    
    int[] randSubset(int[] lst, int nu) {
        return null;
    }

    HeaderAndSecrets create_header(SphinxParams params, byte[][] nodelist, ECPoint[] keys, byte[] dest) {
        byte[][] node_meta = new byte[nodelist.length][];
        for (int i = 0; i < nodelist.length; i++) {
            byte[] node = nodelist[i];
            byte[] nodeLength = {(byte) node.length};
            node_meta[i] = params.concatByteArrays(nodeLength, node);
        }

        int nu = nodelist.length;
        Group_ECC group = params.getGroup();
        BigInteger x = group.genSecret();

        BigInteger blind_factor = x;
        List<HeaderRecord> asbtuples = new ArrayList<HeaderRecord>();

        for (ECPoint k : keys) {
            ECPoint alpha = group.expon(group.getGenerator(), blind_factor);
            ECPoint s = group.expon(k, blind_factor);
            byte[] aes_s = params.getAesKey(s);

            BigInteger b = params.hb(alpha, aes_s);
            blind_factor = blind_factor.multiply(b);
            blind_factor = blind_factor.mod(group.getOrder());

            HeaderRecord headerRecord = new HeaderRecord();
            headerRecord.alpha = alpha;
            headerRecord.s = s;
            headerRecord.b = b;
            headerRecord.aes_s = aes_s;

            asbtuples.add(headerRecord);
        }

        byte[] phi = {};
        int min_len = params.getHeaderLength() - 32;

        for (int i = 1; i < nu; i++) {
            byte[] zeroes1 = new byte[params.getKeyLength() + node_meta[i].length];
            Arrays.fill(zeroes1, (byte) 0x00);
            byte[] plain = params.concatByteArrays(phi, zeroes1);

            byte[] zeroes2 = new byte[min_len];
            Arrays.fill(zeroes2, (byte) 0x00);
            byte[] zeroes2plain = params.concatByteArrays(zeroes2, plain);
            phi = params.xorRho(params.hrho(asbtuples.get(i-1).aes_s), zeroes2plain);
            phi = Arrays.copyOfRange(phi, min_len, phi.length);

            min_len -= node_meta[i].length + params.getKeyLength();
        }

        int len_meta = 0;
        for (int i = 1; i < node_meta.length; i++) {
            len_meta += node_meta[i].length;
        }

        assert(phi.length == len_meta + (nu-1)*params.getKeyLength());

        byte[] destLength = {(byte) dest.length};
        byte[] final_routing = params.concatByteArrays(destLength, dest);

        int random_pad_len = (params.getHeaderLength() - 32) - len_meta - (nu-1)*params.getKeyLength() - final_routing.length;
        assert(random_pad_len >= 0);

        // Stub for testing purposes
        byte[] random_pad = new byte[random_pad_len];

        byte[] beta = params.concatByteArrays(final_routing, random_pad);
        beta = params.xorRho(params.hrho(asbtuples.get(nu - 1).aes_s), beta);
        beta = params.concatByteArrays(beta, phi);

        byte[] gamma = params.mu(params.hmu(asbtuples.get(nu-1).aes_s), beta);

        for (int i = nu - 2; i >= 0; i--) {
            byte[] node_id = node_meta[i+1];

            int plain_beta_len = (params.getHeaderLength() - 32) - params.getKeyLength() - node_id.length;
            byte[] plain_beta = Arrays.copyOf(beta, plain_beta_len);
            byte[] plain = params.concatByteArrays(node_id, gamma, plain_beta);

            beta = params.xorRho(params.hrho(asbtuples.get(i).aes_s), plain);
            gamma = params.mu(params.hmu(asbtuples.get(i).aes_s), beta);
        }


        Header header = new Header();
        header.alpha = asbtuples.get(0).alpha;
        header.beta = beta;
        header.gamma = gamma;

        byte[][] secrets = new byte[asbtuples.size()][];
        for (int i = 0; i < asbtuples.size(); i++) {
            secrets[i] = asbtuples.get(i).aes_s;
        }

        HeaderAndSecrets headerAndSecrets = new HeaderAndSecrets();
        headerAndSecrets.header = header;
        headerAndSecrets.secrets = secrets;

        return headerAndSecrets;
    }

    HeaderAndDelta create_forward_message(SphinxParams params, byte[][] nodelist, ECPoint[] keys, DestinationAndMessage destinationAndMessage) throws IOException {
        MessageBufferPacker packer;

        packer = MessagePack.newDefaultBufferPacker();
        packer.packArrayHeader(1);
        packer.packString(DEST_FLAG);
        packer.close();

        byte[] finalDestination = packer.toByteArray();
        HeaderAndSecrets headerAndSecrets = create_header(params, nodelist, keys, finalDestination);

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

        byte[] body = params.concatByteArrays(zeroes, encodedDestAndMsg);
        body = padBody(params, params.getBodyLength(), body);

        byte[][] secrets = headerAndSecrets.secrets;
        byte[] delta = params.pi(params.hpi(secrets[nodelist.length - 1]), body);

        for (int i = nodelist.length - 2; i >= 0; i--) {
            delta = params.pi(params.hpi(secrets[i]), delta);
        }

        HeaderAndDelta headerAndDelta = new HeaderAndDelta();
        headerAndDelta.header = headerAndSecrets.header;
        headerAndDelta.delta = delta;

        return headerAndDelta;
    }

    Surb create_surb(SphinxParams params, byte[][] nodelist, byte[][] keys, byte[] dest) {
        return null;
    }

    HeaderAndDelta package_surb(SphinxParams params, NymTuple nymTuple, byte[] message) {
        return null;
    }

    DestinationAndMessage receiveForward(SphinxParams params, byte[] delta) throws IOException {
        byte[] zeroes = new byte[params.getKeyLength()];
        Arrays.fill(zeroes, (byte) 0x00);

        assert(Arrays.equals(Arrays.copyOf(delta, params.getKeyLength()), zeroes));

        byte[] encodedDestAndMsg = unpadBody(Arrays.copyOfRange(delta, params.getKeyLength(), delta.length));
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(encodedDestAndMsg);
        unpacker.unpackArrayHeader();
        int destLength = unpacker.unpackBinaryHeader();
        byte[] destination = unpacker.readPayload(destLength);
        int msgLength = unpacker.unpackBinaryHeader();
        byte[] message = unpacker.readPayload(msgLength);
        unpacker.close();

        DestinationAndMessage destinationAndMessage = new DestinationAndMessage();
        destinationAndMessage.destination = destination;
        destinationAndMessage.message = message;

        return destinationAndMessage;
    }

    byte[] receiveSurb(SphinxParams params, byte[][] keytuple, byte[] delta) {
        return null;
    }

    byte[] pack_message(SphinxPacket sphinxPacket) throws IOException {
        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();

        int headerLength = sphinxPacket.paramLengths.maxLength;
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

    SphinxPacket unpack_message(byte[] m) {
        return null;
    }

    byte[] packECPoint(ECPoint ecPoint) throws IOException {
        byte[] encodedEcPoint = ecPoint.getEncoded(true);
        int nid = 713;

        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        packer.packArrayHeader(2);
        packer.packInt(nid);
        packer.packBinaryHeader(encodedEcPoint.length);
        packer.writePayload(encodedEcPoint);
        packer.close();

        return packer.toByteArray();
    }
}
