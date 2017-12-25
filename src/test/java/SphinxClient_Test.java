import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.junit.Test;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.math.BigInteger;
import java.util.HashMap;

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
        for (int i = 0; i < use_nodes.length; i++) {
            nodes_routing[i] = client.encodeNode(use_nodes[i]);
        }

        ECPoint[] node_keys = new ECPoint[use_nodes.length];
        for (int i = 0; i < use_nodes.length; i++) {
            node_keys[i] = pkiPub.get(use_nodes[i]).y;
        }

        byte[] dest = "bob".getBytes();
        byte[] message = "this is a test".getBytes();

        DestinationAndMessage destinationAndMessage = new DestinationAndMessage();
        destinationAndMessage.destination = dest;
        destinationAndMessage.message = message;

        HeaderAndDelta headerAndDelta = client.createForwardMessage(params, nodes_routing, node_keys, destinationAndMessage);

        ParamLengths paramLengths = new ParamLengths(params.getHeaderLength(), params.getBodyLength());

        SphinxPacket sphinxPacket = new SphinxPacket();
        sphinxPacket.paramLengths = paramLengths;
        sphinxPacket.headerAndDelta = headerAndDelta;

        byte[] bin_message = client.packMessage(sphinxPacket);
        SphinxPacket unpackedSphinxPacket = client.unpackMessage(bin_message);
        ParamLengths unpackedParamLengths = unpackedSphinxPacket.paramLengths;
        HeaderAndDelta unpackedHeaderAndDelta = unpackedSphinxPacket.headerAndDelta;

        assertEquals(params.getHeaderLength(), unpackedParamLengths.headerLength);
        assertEquals(params.getBodyLength(), unpackedParamLengths.bodyLength);

        assertEquals(headerAndDelta.header.alpha, unpackedHeaderAndDelta.header.alpha);
        assertArrayEquals(headerAndDelta.header.beta, unpackedHeaderAndDelta.header.beta);
        assertArrayEquals(headerAndDelta.header.gamma, unpackedHeaderAndDelta.header.gamma);
        assertArrayEquals(headerAndDelta.delta, unpackedHeaderAndDelta.delta);

        BigInteger x = pkiPriv.get(use_nodes[0]).x;

        MessageUnpacker unpacker;

        while (true) {
            ProcessedPacket ret = SphinxNode.sphinxProcess(params, x, headerAndDelta);
            headerAndDelta = ret.headerAndDelta;

            byte[] encodedRouting = ret.routing;

            unpacker = MessagePack.newDefaultUnpacker(encodedRouting);
            int routingLen = unpacker.unpackArrayHeader();
            String flag = unpacker.unpackString();

            assertTrue(flag.equals(client.RELAY_FLAG) || flag.equals(client.DEST_FLAG));

            if (flag.equals(client.RELAY_FLAG)) {
                int addr = unpacker.unpackInt();
                x = pkiPriv.get(addr).x;

                unpacker.close();
            } else if (flag.equals(client.DEST_FLAG)) {
                unpacker.close();

                assertEquals(1, routingLen);

                byte[] zeroes = new byte[params.getKeyLength()];
                java.util.Arrays.fill(zeroes, (byte) 0x00);

                assertArrayEquals(zeroes, Arrays.copyOf(ret.headerAndDelta.delta, 16));

                DestinationAndMessage destAndMsg = client.receiveForward(params, ret.headerAndDelta.delta);

                assertArrayEquals(dest, destAndMsg.destination);
                assertArrayEquals(message, destAndMsg.message);

                break;
            }
        }

        byte[] surbDest = "myself".getBytes();
        message = "This is a reply".getBytes();

        Surb surb = client.createSurb(params, nodes_routing, node_keys, surbDest);
        headerAndDelta = client.packageSurb(params, surb.nymTuple, message);

        x = pkiPriv.get(use_nodes[0]).x;

        while (true) {
            ProcessedPacket ret = SphinxNode.sphinxProcess(params, x, headerAndDelta);
            headerAndDelta = ret.headerAndDelta;

            byte[] encodedRouting = ret.routing;

            unpacker = MessagePack.newDefaultUnpacker(encodedRouting);
            int routingLen = unpacker.unpackArrayHeader();
            String flag = unpacker.unpackString();

            assertTrue(flag.equals(client.RELAY_FLAG) || flag.equals(client.SURB_FLAG));

            if (flag.equals(client.RELAY_FLAG)) {
                int addr = unpacker.unpackInt();
                x = pkiPriv.get(addr).x;

                unpacker.close();
            } else if (flag.equals(client.SURB_FLAG)) {
                unpacker.close();
                break;
            }
        }

        byte[] received = client.receiveSurb(params, surb.keytuple, headerAndDelta.delta);

        assertArrayEquals(message, received);
    }
}
