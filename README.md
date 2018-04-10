Java Sphinx
===========
[![Build Status](https://travis-ci.org/rsoultanaev/java-sphinx.svg?branch=master)](https://travis-ci.org/rsoultanaev/java-sphinx)
[![codecov](https://codecov.io/gh/rsoultanaev/java-sphinx/branch/master/graph/badge.svg)](https://codecov.io/gh/rsoultanaev/java-sphinx)

Java implementation of the sphinx packet format.

This is a port of the [Python implementation of the sphinx software.](https://github.com/UCL-InfoSec/sphinx)

# Usage

## Encoding forward messages

The following import statements are required for the snippets in this section:

```java
import java.math.BigInteger;
import java.util.HashMap;
import org.bouncycastle.math.ec.ECPoint;
import com.robertsoultanaev.javasphinx.*;
```

To package or process sphinx messages create a new SphinxParams object:

```java
SphinxParams params = new SphinxParams();
```

Rudimentary Public Key Information is required to encode Sphinx packets. The following snippet generates a mapping from mix node id's to their public & private key entries:

```java
class PkiEntry {
    BigInteger priv;
    ECPoint pub;

    public PkiEntry(BigInteger priv, ECPoint pub) {
        this.priv = priv;
        this.pub = pub;
    }
}

HashMap<Integer, PkiEntry> pki = new HashMap<Integer, PkiEntry>();

for (int i = 0; i < 10; i++) {
    int nodeId = i;
    BigInteger priv = params.getGroup().genSecret();
    ECPoint pub = params.getGroup().expon(params.getGroup().getGenerator(), priv);

    pki.put(nodeId, new PkiEntry(priv, pub));
}
```

Before encoding a Sphinx packet, the route through the mix network must be selected. This can be done with the `SphinxClient.randSubset()` method:

```java
Object[] pubKeys = pki.keySet().toArray();
int[] nodePool = new int[pubKeys.length];
for (int i = 0; i < nodePool.length; i++) {
    nodePool[i] = (Integer) pubKeys[i];
}
int[] useNodes = SphinxClient.randSubset(nodePool, r);
```

The encoding function takes as argument (among other things) an array of nodes used for routing the packet, where each element is a byte array produced from `SphinxClient.encodeNode()`, and an array of the corresponding public keys of type `org.bouncycastle.math.ec.ECPoint`:

```java
byte[][] nodesRouting = new byte[useNodes.length][];
for (int i = 0; i < useNodes.length; i++) {
    nodesRouting[i] = SphinxClient.encodeNode(useNodes[i]);
}

ECPoint[] nodeKeys = new ECPoint[useNodes.length];
for (int i = 0; i < useNodes.length; i++) {
    nodeKeys[i] = pkiPub.get(useNodes[i]).y;
}
``` 

Finally, to create and package a forward Sphinx message:

```java
byte[] dest = "bob".getBytes();
byte[] message = "this is a test".getBytes();

DestinationAndMessage destinationAndMessage = new DestinationAndMessage(dest, message);
HeaderAndDelta headerAndDelta = SphinxClient.createForwardMessage(params, nodesRouting, nodeKeys, destinationAndMessage);

ParamLengths paramLengths = new ParamLengths(params.getHeaderLength(), params.getBodyLength());
SphinxPacket sphinxPacket = new SphinxPacket(paramLengths, headerAndDelta);
byte[] binMessage = SphinxClient.packMessage(sphinxPacket);
```

## Processing Sphinx messages at a mix

In addition to the import statements in the previous section, unpacking and processing messages requires the use of MessagePack:

```java
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;
```

Before processing the message, the mix needs to unpack the message from binary format:

```java
SphinxPacket unpackedSphinxPacket = SphinxClient.unpackMessage(binMessage);
HeaderAndDelta unpackedHeaderAndDelta = unpackedSphinxPacket.headerAndDelta;
```

The header and delta of the packet are the processed as follows (some sections are commented as they depend on the specific implementation of a node):

```java
SphinxParams params = new SphinxParams();
MessageUnpacker unpacker;

BigInteger currentNodeKey = /* The private key of the mix node */;

ProcessedPacket ret = SphinxNode.sphinxProcess(params, currentNodeKey, unpackedHeaderAndDelta);
headerAndDelta = ret.headerAndDelta;

byte[] encodedRouting = ret.routing;

unpacker = MessagePack.newDefaultUnpacker(encodedRouting);
int routingLen = unpacker.unpackArrayHeader();
String flag = unpacker.unpackString();

if (flag.equals(SphinxClient.RELAY_FLAG)) {
    int nextNodeId = unpacker.unpackInt();
    unpacker.close();
    
    /* Forward to node designated by nextNodeId */
} else if (flag.equals(SphinxClient.DEST_FLAG)) {
    unpacker.close();

    DestinationAndMessage destAndMsg = SphinxClient.receiveForward(params, ret.macKey, ret.headerAndDelta.delta);
    
    byte[] finalDestination = destAndMsg.destination;
    byte[] finalMessage = destAndMsg.message;

    /* Forward finalMessage to finalDestination */
}
```

## Single-use reply Blocks

Sphinx supports the ability to reply to anonymous senders, if they include a single-use reply block (SURB) in their forward message. To create a SURB the sender uses the `SphinxClient.createSurb()` method:

```java
byte[] surbDest = "myself".getBytes();
Surb surb = SphinxClient.createSurb(params, nodesRouting, nodeKeys, surbDest);
```  

The `Surb` type contains three fields - `xid` is the identifier of this SURB, `keytuple` is used to receive messages addressed to a SURB, and `nymtuple` is the structure that needs to be encoded in the payload of the forward message, since it is used by the recipient to reply to the message. To reply to a SURB message:

```java
byte[] message = "This is a reply".getBytes();
HeaderAndDelta headerAndDelta = SphinxClient.packageSurb(params, surb.nymTuple, message);
```

The header and delta are routed through the mix network like forward messages, except for the final mix:

```java
/* Same routing code as for forward messages */
 else if (flag.equals(SphinxClient.SURB_FLAG)) {
    int destLength = unpacker.unpackBinaryHeader();
    byte[] finalDest = unpacker.readPayload(destLength);
    int surbIdLength = unpacker.unpackBinaryHeader();
    byte[] finalSurbId = unpacker.readPayload(surbIdLength);
    unpacker.close();
    
    /* Relay finalSurbId and headerAndDelta.delta to finalDest */
}
```

Finally at the recipient of the reply, `finalSurbId` is used to find the corresponding `keytuple` to receive the reply:

```java
byte[] received = SphinxClient.receiveSurb(params, surb.keytuple, headerAndDelta.delta);
```