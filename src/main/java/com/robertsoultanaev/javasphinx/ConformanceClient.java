package com.robertsoultanaev.javasphinx;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

public class ConformanceClient {
    public static void main(String args[]) throws Exception {
        byte[] dest = Base64.decode(args[0]);
        byte[] message = Base64.decode(args[1]);

        int numNodes = args.length - 2;
        byte[][] nodesRouting = new byte[numNodes][];
        ECPoint[] nodeKeys = new ECPoint[numNodes];

        for (int i = 0; i < numNodes; i++) {
            String[] split = args[2 + i].split(":");
            int nodeId = Integer.parseInt(split[0]);
            nodesRouting[i] = SphinxClient.encodeNode(nodeId);

            byte[] encodedKey = Base64.decode(split[1]);
            nodeKeys[i] = Util.decodeECPoint(encodedKey);
        }

        DestinationAndMessage destinationAndMessage = new DestinationAndMessage(dest, message);

        SphinxParams params = new SphinxParams();
        HeaderAndDelta headerAndDelta = SphinxClient.createForwardMessage(params, nodesRouting, nodeKeys, destinationAndMessage);
        ParamLengths paramLengths = new ParamLengths(params.getHeaderLength(), params.getBodyLength());
        SphinxPacket sphinxPacket = new SphinxPacket(paramLengths, headerAndDelta);
        byte[] binMessage = SphinxClient.packMessage(sphinxPacket);

        System.out.write(binMessage);
    }
}
