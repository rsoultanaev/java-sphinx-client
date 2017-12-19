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

    byte[] routePack(byte[] info) {
        return null;
    }

    byte[] pfDecode(SphinxParams param, byte[] packed) {
        return null;
    }

    int[] randSubset(int[] lst, int nu) {
        return null;
    }

    byte[] create_header(SphinxParams params, byte[][] nodelist, byte[][] keys, byte[] dest) {
        return null;
    }

    byte[] create_forward_message(SphinxParams params, byte[][] nodelist, byte[][] keys, byte[] dest, byte[] msg) {
        return null;
    }

    byte[] create_surb(SphinxParams params, byte[][] nodelist, byte[][] keys, byte[] dest) {
        return null;
    }

    byte[] package_surb(SphinxParams params, byte[] n0, byte[] header0, byte[] ktilde, byte[] message) {
        return null;
    }

    byte[] receiveForward(SphinxParams params, byte[] delta) {
        return null;
    }

    byte[] receiveSurb(SphinxParams params, byte[][] keytuple, byte[] delta) {
        return null;
    }

    byte[] pack_message(SphinxParams params, byte[] m) {
        return null;
    }

    byte[] unpack_message(HashMap<ParamLens, SphinxParams> params_dict, byte[] m) {
        return null;
    }
}
