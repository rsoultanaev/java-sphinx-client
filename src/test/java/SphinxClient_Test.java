import com.robertsoultanaev.javasphinx.*;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.junit.Before;
import org.junit.Test;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.math.BigInteger;
import java.util.HashMap;

import static org.junit.Assert.*;

public class SphinxClient_Test {
    class PkiEntry {
        BigInteger x;
        ECPoint y;

        public PkiEntry(BigInteger x, ECPoint y) {
            this.x = x;
            this.y = y;
        }
    }

    private SphinxParams params;
    private HashMap<Integer, PkiEntry> pkiPriv;
    private byte[][] nodesRouting;
    private ECPoint[] nodeKeys;
    private int[] useNodes;

    @Before
    public void setUp() throws Exception {
        params = new SphinxParams();

        int r = 5;

        pkiPriv = new HashMap<Integer, PkiEntry>();
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
        useNodes = SphinxClient.randSubset(nodePool, r);

        nodesRouting = new byte[useNodes.length][];
        for (int i = 0; i < useNodes.length; i++) {
            nodesRouting[i] = SphinxClient.encodeNode(useNodes[i]);
        }

        nodeKeys = new ECPoint[useNodes.length];
        for (int i = 0; i < useNodes.length; i++) {
            nodeKeys[i] = pkiPub.get(useNodes[i]).y;
        }
    }

    @Test
    public void encodeAndDecode() throws Exception {
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
    }

    @Test
    public void encodeAndDecodeMaxMessageLength() throws Exception {
        byte[] dest = "bob".getBytes();
        byte[] message = new byte[SphinxClient.getMaxPayloadSize(params) - dest.length];
        Arrays.fill(message, (byte) 0xaa);

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
    }

    @Test
    public void routeSphinxMessage() throws Exception {
        byte[] dest = "bob".getBytes();
        byte[] message = "this is a test".getBytes();

        DestinationAndMessage destinationAndMessage = new DestinationAndMessage(dest, message);

        HeaderAndDelta headerAndDelta = SphinxClient.createForwardMessage(params, nodesRouting, nodeKeys, destinationAndMessage);

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
    }

    @Test
    public void routeSphinxMessageMaxMessageLength() throws Exception {
        byte[] dest = "bob".getBytes();
        byte[] message = new byte[SphinxClient.getMaxPayloadSize(params) - dest.length];
        Arrays.fill(message, (byte) 0xaa);

        DestinationAndMessage destinationAndMessage = new DestinationAndMessage(dest, message);

        HeaderAndDelta headerAndDelta = SphinxClient.createForwardMessage(params, nodesRouting, nodeKeys, destinationAndMessage);

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
    }

    @Test
    public void routeSurb() throws Exception {
        byte[] surbDest = "myself".getBytes();
        byte[] message = "This is a reply".getBytes();

        Surb surb = SphinxClient.createSurb(params, nodesRouting, nodeKeys, surbDest);
        HeaderAndDelta headerAndDelta = SphinxClient.packageSurb(params, surb.nymTuple, message);

        BigInteger x = pkiPriv.get(useNodes[0]).x;
        MessageUnpacker unpacker;

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

    @Test(expected = SphinxException.class)
    public void randSubsetBadNu() throws Exception {
        int[] nodePool = {0,0,0,0,0};
        SphinxClient.randSubset(nodePool, nodePool.length + 1);
    }

    @Test(expected = SphinxException.class)
    public void receiveForwardBadDelta() throws Exception {
        byte[] dest = "bob".getBytes();
        byte[] message = "this is a test".getBytes();

        DestinationAndMessage destinationAndMessage = new DestinationAndMessage(dest, message);

        HeaderAndDelta headerAndDelta = SphinxClient.createForwardMessage(params, nodesRouting, nodeKeys, destinationAndMessage);
        headerAndDelta.delta[0] = 1;
        SphinxClient.receiveForward(params, headerAndDelta.delta);
    }

    @Test(expected = SphinxException.class)
    public void receiveSurbBadDelta() throws Exception {
        byte[] surbDest = "myself".getBytes();
        byte[] message = "This is a reply".getBytes();

        Surb surb = SphinxClient.createSurb(params, nodesRouting, nodeKeys, surbDest);
        HeaderAndDelta headerAndDelta = SphinxClient.packageSurb(params, surb.nymTuple, message);
        headerAndDelta.delta[0] = 1;
        SphinxClient.receiveSurb(params, surb.keytuple, headerAndDelta.delta);
    }

    @Test(expected = SphinxException.class)
    public void createForwardDestTooLong() throws Exception {
        byte[] dest = new byte[SphinxClient.MAX_DEST_SIZE + 1];
        byte[] message = "this is a test".getBytes();

        DestinationAndMessage destinationAndMessage = new DestinationAndMessage(dest, message);

        SphinxClient.createForwardMessage(params, nodesRouting, nodeKeys, destinationAndMessage);
    }

    @Test(expected = SphinxException.class)
    public void createForwardDestAndMessageTooLong() throws Exception {
        byte[] dest = "bob".getBytes();
        byte[] message = new byte[(SphinxClient.getMaxPayloadSize(params) - dest.length) + 1];

        DestinationAndMessage destinationAndMessage = new DestinationAndMessage(dest, message);

        SphinxClient.createForwardMessage(params, nodesRouting, nodeKeys, destinationAndMessage);
    }
}
