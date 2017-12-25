import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.junit.Test;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Set;

import static org.junit.Assert.*;

public class SphinxClient_Test {
    @Test
    public void test() throws Exception {
        class PkiEntry {
            BigInteger x;
            ECPoint y;
        }

        SphinxParams params = new SphinxParams();
        SphinxClient client = new SphinxClient();

        int r = 5;

        HashMap<Integer, PkiEntry> pkiPriv = new HashMap<Integer, PkiEntry>();
        HashMap<Integer, PkiEntry> pkiPub = new HashMap<Integer, PkiEntry>();

        for (int i = 0; i < 10; i++) {
            BigInteger x = params.getGroup().genSecret();
            ECPoint y = params.getGroup().expon(params.getGroup().getGenerator(), x);

            PkiEntry privEntry = new PkiEntry();
            PkiEntry pubEntry = new PkiEntry();

            privEntry.x = x;
            privEntry.y = y;
            pkiPriv.put(i, privEntry);

            pubEntry.x = null;
            pubEntry.y = y;
            pkiPub.put(i, pubEntry);
        }

        Object[] pubKeys = pkiPub.keySet().toArray();
        int[] node_pool = new int[pubKeys.length];
        for (int i = 0; i < node_pool.length; i++) {
            node_pool[i] = (Integer) pubKeys[i];
        }
        int[] use_nodes = client.randSubset(node_pool, r);

        byte[][] nodes_routing = new byte[use_nodes.length][];
        for (int i = 0; i < nodes_routing.length; i++) {
            nodes_routing[i] = client.nodeEncoding(use_nodes[i]);
        }

        ECPoint[] node_keys = new ECPoint[use_nodes.length];
        for (int i = 0; i < node_keys.length; i++) {
            node_keys[i] = pkiPub.get(i).y;
        }

        byte[] dest = "bob".getBytes();
        byte[] message = "this is a test".getBytes();

        DestinationAndMessage destinationAndMessage = new DestinationAndMessage();
        destinationAndMessage.destination = dest;
        destinationAndMessage.message = message;

        HeaderAndDelta headerAndDelta = client.create_forward_message(params, nodes_routing, node_keys, destinationAndMessage);

        ParamLengths paramLengths = new ParamLengths(params.getHeaderLength(), params.getBodyLength());

        SphinxPacket sphinxPacket = new SphinxPacket();
        sphinxPacket.paramLengths = paramLengths;
        sphinxPacket.headerAndDelta = headerAndDelta;

        byte[] bin_message = client.pack_message(sphinxPacket);
        SphinxPacket unpackedSphinxPacket = client.unpack_message(bin_message);
        ParamLengths unpackedParamLengths = unpackedSphinxPacket.paramLengths;
        HeaderAndDelta unpackedHeaderAndDelta = unpackedSphinxPacket.headerAndDelta;

        assertEquals(params.getHeaderLength(), unpackedParamLengths.maxLength);
        assertEquals(params.getBodyLength(), unpackedParamLengths.bodyLength);

        assertEquals(headerAndDelta.header.alpha, unpackedHeaderAndDelta.header.alpha);
        assertArrayEquals(headerAndDelta.header.beta, unpackedHeaderAndDelta.header.beta);
        assertArrayEquals(headerAndDelta.header.gamma, unpackedHeaderAndDelta.header.gamma);
        assertArrayEquals(headerAndDelta.delta, unpackedHeaderAndDelta.delta);
    }

    /*
    x = pkiPriv[use_nodes[0]].x

    i = 0
    while True:

        ret = sphinx_process(params, x, header, delta)
        (tag, B, (header, delta)) = ret
        routing = PFdecode(params, B)

        print("round %d" % i)
        i += 1

        # print("Type: %s" % typex)
        if routing[0] == Relay_flag:
            addr = routing[1]
            x = pkiPriv[addr].x
        elif routing[0] == Dest_flag:
            assert len(routing) == 1
            assert delta[:16] == b"\x00" * params.k
            dec_dest, dec_msg = receive_forward(params, delta)
            assert dec_dest == dest
            assert dec_msg == message

            break
        else:
            print("Error")
            assert False
            break

    # Test the nym creation
    surbid, surbkeytuple, nymtuple = create_surb(params, nodes_routing, node_keys, b"myself")

    message = b"This is a reply"
    header, delta = package_surb(params, nymtuple, message)

    x = pkiPriv[use_nodes[0]].x

    while True:
        ret = sphinx_process(params, x, header, delta)
        (tag, B, (header, delta)) = ret
        routing = PFdecode(params, B)

        if routing[0] == Relay_flag:
            flag, addr = routing
            x = pkiPriv[addr].x
        elif routing[0] == Surb_flag:
            flag, dest, myid = routing
            break

    received = receive_surb(params, surbkeytuple, delta)
    assert received == message

    */

}
