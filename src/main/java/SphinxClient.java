import java.util.HashMap;

public class SphinxClient {
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

    HeaderAndDelta create_forward_message(SphinxParams params, byte[][] nodelist, byte[][] keys, byte[] dest, byte[] msg) {
        return null;
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
