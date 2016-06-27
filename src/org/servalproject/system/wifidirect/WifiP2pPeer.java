package org.servalproject.system.wifidirect;

import android.net.wifi.p2p.nsd.WifiP2pServiceInfo;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;

public class WifiP2pPeer {
    private final int BUFFER_SIZE = 65536;
    private final int BUFFER_THRESH = 512;
    private ByteBuffer sendBuffer = ByteBuffer.allocate(BUFFER_SIZE);
    private ByteBuffer recvBuffer = ByteBuffer.allocate(BUFFER_SIZE);
    private int seqNumber = 0;
    private int ackNumber = 0;
    private long lastSeen;
    private Collection<WifiP2pServiceInfo> serviceSet = new ArrayList<WifiP2pServiceInfo>();

    WifiP2pPeer() {
        resetLastSeen();
    }

    /* Returns true is the send buffers is over the buffer full threshold */
    public boolean isFull() {
        return (sendBuffer.position() >= BUFFER_THRESH);
    }

    /* Resets the last seen time to the current time */
    public void resetLastSeen() {
        lastSeen = System.nanoTime();
    }

    /* Returns the last time this peer was seen */
    public long getLastSeen(){
        return lastSeen;
    }

    /* Get the current acknowledgment number for this peer. */
    public int getAckNumber() {
        return ackNumber;
    }

    /* Removes the acknowledged data from the send buffer and updates the sequence number. */
    public synchronized void updateSequence(int ackReceived) {
        int bytesAcknowledged = ackReceived - seqNumber;
        sendBuffer.flip();
        sendBuffer.position(bytesAcknowledged);
        sendBuffer.compact();
        seqNumber += bytesAcknowledged;
    }

    /* Get the current sequence number for this peer. */
    public int getSequenceNumber() {
        return seqNumber;
    }

    /* Set the current set of services(posts) for this peer */
    public void setServiceSet(Collection<WifiP2pServiceInfo> serviceSet) {
        this.serviceSet = serviceSet;
    }

    /* Get the current set of services(posts) for this peer. Needed when deleting posts. */
    public Collection<WifiP2pServiceInfo> getServiceSet() {
        return serviceSet;
    }

    /* Inserts the packet length and data into the send buffer */
    public synchronized void queuePacket(ByteBuffer packet) {
        sendBuffer.putShort((short) packet.remaining());
        sendBuffer.put(packet);
    }

    /* Retrieves up to the specified number of bytes from the send buffer. This may include
     previously retrieved bytes. Used when updating a post for this peer. */
    public synchronized byte[] getPostData(int maxPostData) {
        int count = Math.min(maxPostData, sendBuffer.position());
        byte[] postData = new byte[count];

        for (int i = 0; i < count; i++) {
            postData[i] = sendBuffer.get(i);
        }
        return postData;
    }

    /* Determines what bytes are new and adds them to the receive buffer, then updates the
     acknowledgment number. */
    public synchronized void recvData(int seqNumber, byte[] data) {
        int offset = ackNumber - seqNumber;
        int count = data.length - offset;
        recvBuffer.put(data, offset, count);
        ackNumber += count;
    }

    /* Determines if a whole packet is available in the receive buffer and returns it, removing
     the bytes from the buffer. */
    public synchronized byte[] getPacket() {
        if (recvBuffer.remaining() > 2) {
            short packetSize = recvBuffer.getShort(0);
            if (recvBuffer.position() >= packetSize + 2) {
                byte[] packet = new byte[packetSize];
                recvBuffer.flip();
                recvBuffer.position(2);
                recvBuffer.get(packet);
                recvBuffer.compact();
                return packet;
            }
        }
        return null;
    }
}