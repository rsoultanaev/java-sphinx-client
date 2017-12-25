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

            public PkiEntry(BigInteger x, ECPoint y) {
                this.x = x;
                this.y = y;
            }
        }

        SphinxParams params = new SphinxParams();

        int r = 5;

        HashMap<Integer, PkiEntry> pkiPriv = new HashMap<Integer, PkiEntry>();
        HashMap<Integer, PkiEntry> pkiPub = new HashMap<Integer, PkiEntry>();

        for (int i = 0; i < 10; i++) {
            BigInteger x = params.getGroup().genSecret();
            ECPoint y = params.getGroup().expon(params.getGroup().getGenerator(), x);

            PkiEntry privEntry = new PkiEntry(x, y);
            PkiEntry pubEntry = new PkiEntry(null, y);

            pkiPriv.put(i, privEntry);
            pkiPub.put(i, pubEntry);
        }

        Object[] pubKeys = pkiPub.keySet().toArray();
        int[] nodePool = new int[pubKeys.length];
        for (int i = 0; i < nodePool.length; i++) {
            nodePool[i] = (Integer) pubKeys[i];
        }
        int[] useNodes = SphinxClient.randSubset(nodePool, r);

        byte[][] nodesRouting = new byte[useNodes.length][];
        for (int i = 0; i < useNodes.length; i++) {
            nodesRouting[i] = SphinxClient.encodeNode(useNodes[i]);
        }

        ECPoint[] nodeKeys = new ECPoint[useNodes.length];
        for (int i = 0; i < useNodes.length; i++) {
            nodeKeys[i] = pkiPub.get(useNodes[i]).y;
        }

        byte[] dest = "bob".getBytes();
        byte[] message = "this is a test".getBytes();

        DestinationAndMessage destinationAndMessage = new DestinationAndMessage(dest, message);

        HeaderAndDelta headerAndDelta = SphinxClient.createForwardMessage(params, nodesRouting, nodeKeys, destinationAndMessage);

        ParamLengths paramLengths = new ParamLengths(params.getHeaderLength(), params.getBodyLength());

        SphinxPacket sphinxPacket = new SphinxPacket(paramLengths, headerAndDelta);

        byte[] binMessage = SphinxClient.packMessage(sphinxPacket);
        SphinxPacket unpackedSphinxPacket = SphinxClient.unpackMessage(binMessage);
        ParamLengths unpackedParamLengths = unpackedSphinxPacket.paramLengths;
        HeaderAndDelta unpackedHeaderAndDelta = unpackedSphinxPacket.headerAndDelta;

        assertEquals(params.getHeaderLength(), unpackedParamLengths.headerLength);
        assertEquals(params.getBodyLength(), unpackedParamLengths.bodyLength);

        assertEquals(headerAndDelta.header.alpha, unpackedHeaderAndDelta.header.alpha);
        assertArrayEquals(headerAndDelta.header.beta, unpackedHeaderAndDelta.header.beta);
        assertArrayEquals(headerAndDelta.header.gamma, unpackedHeaderAndDelta.header.gamma);
        assertArrayEquals(headerAndDelta.delta, unpackedHeaderAndDelta.delta);

        BigInteger x = pkiPriv.get(useNodes[0]).x;

        MessageUnpacker unpacker;

        while (true) {
            ProcessedPacket ret = SphinxNode.sphinxProcess(params, x, headerAndDelta);
            headerAndDelta = ret.headerAndDelta;

            byte[] encodedRouting = ret.routing;

            unpacker = MessagePack.newDefaultUnpacker(encodedRouting);
            int routingLen = unpacker.unpackArrayHeader();
            String flag = unpacker.unpackString();

            assertTrue(flag.equals(SphinxClient.RELAY_FLAG) || flag.equals(SphinxClient.DEST_FLAG));

            if (flag.equals(SphinxClient.RELAY_FLAG)) {
                int addr = unpacker.unpackInt();
                x = pkiPriv.get(addr).x;

                unpacker.close();
            } else if (flag.equals(SphinxClient.DEST_FLAG)) {
                unpacker.close();

                assertEquals(1, routingLen);

                byte[] zeroes = new byte[params.getKeyLength()];
                java.util.Arrays.fill(zeroes, (byte) 0x00);

                assertArrayEquals(zeroes, Arrays.copyOf(ret.headerAndDelta.delta, 16));

                DestinationAndMessage destAndMsg = SphinxClient.receiveForward(params, ret.headerAndDelta.delta);

                assertArrayEquals(dest, destAndMsg.destination);
                assertArrayEquals(message, destAndMsg.message);

                break;
            }
        }

        byte[] surbDest = "myself".getBytes();
        message = "This is a reply".getBytes();

        Surb surb = SphinxClient.createSurb(params, nodesRouting, nodeKeys, surbDest);
        headerAndDelta = SphinxClient.packageSurb(params, surb.nymTuple, message);

        x = pkiPriv.get(useNodes[0]).x;

        while (true) {
            ProcessedPacket ret = SphinxNode.sphinxProcess(params, x, headerAndDelta);
            headerAndDelta = ret.headerAndDelta;

            byte[] encodedRouting = ret.routing;

            unpacker = MessagePack.newDefaultUnpacker(encodedRouting);
            unpacker.unpackArrayHeader();
            String flag = unpacker.unpackString();

            assertTrue(flag.equals(SphinxClient.RELAY_FLAG) || flag.equals(SphinxClient.SURB_FLAG));

            if (flag.equals(SphinxClient.RELAY_FLAG)) {
                int addr = unpacker.unpackInt();
                x = pkiPriv.get(addr).x;

                unpacker.close();
            } else if (flag.equals(SphinxClient.SURB_FLAG)) {
                unpacker.close();
                break;
            }
        }

        byte[] received = SphinxClient.receiveSurb(params, surb.keytuple, headerAndDelta.delta);

        assertArrayEquals(message, received);
    }
}
