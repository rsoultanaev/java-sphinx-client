import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;

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

    byte[] padBody(int msgtotalsize, byte[] body) {
        return null;
    }

    byte[] unpadBody(byte[] body) {
        return null;
    }

    byte[] nodeEncoding(int idnum) {
        return null;
    }
    
    int[] randSubset(int[] lst, int nu) {
        return null;
    }

    HeaderAndSecrets create_header(SphinxParams params, byte[][] nodelist, byte[][] keys, byte[] dest) {
        return null;
    }

    HeaderAndDelta create_forward_message(SphinxParams params, byte[][] nodelist, byte[][] keys, DestinationAndMessage destinationAndMessage) throws IOException {
        MessageBufferPacker packer;

        packer = MessagePack.newDefaultBufferPacker();
        packer.packArrayHeader(1);
        packer.packString(DEST_FLAG);
        packer.close();

        byte[] finalDestination = packer.toByteArray();
        HeaderAndSecrets headerAndSecrets = create_header(params, nodelist, keys, finalDestination);

        packer = MessagePack.newDefaultBufferPacker();
        packer.packBinaryHeader(destinationAndMessage.destination.length);
        packer.writePayload(destinationAndMessage.destination);
        packer.packBinaryHeader(destinationAndMessage.message.length);
        packer.writePayload(destinationAndMessage.message);
        packer.close();

        byte[] encodedDestAndMsg = packer.toByteArray();

        byte[] zeroes = new byte[params.getKeyLength()];
        Arrays.fill(zeroes, (byte) 0x00);

        byte[] body = params.concatByteArrays(zeroes, encodedDestAndMsg);
        body = padBody(params.getBodyLength(), body);

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

    DestinationAndMessage receiveForward(SphinxParams params, byte[] delta) {
        return null;
    }

    byte[] receiveSurb(SphinxParams params, byte[][] keytuple, byte[] delta) {
        return null;
    }

    byte[] pack_message(SphinxParams params, SphinxPacket sphinxPacket) {
        return null;
    }

    SphinxPacket unpack_message(HashMap<ParamLengths, SphinxParams> params_dict, byte[] m) {
        return null;
    }
}
