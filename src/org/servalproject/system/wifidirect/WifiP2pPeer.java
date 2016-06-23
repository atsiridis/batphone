package org.servalproject.system.wifidirect;

import android.net.wifi.p2p.nsd.WifiP2pServiceInfo;
import android.util.Log;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;

public class WifiP2pPeer {
    private static final String TAG = "OS3";
    private final int BUFFER_SIZE = 65536;
    private ByteBuffer sendBuffer = ByteBuffer.allocate(BUFFER_SIZE);
    private ByteBuffer recvBuffer = ByteBuffer.allocate(BUFFER_SIZE);
    private int seqNumber = 0;
    private int ackNumber = 0;
    private long lastSeen;
    private Collection<WifiP2pServiceInfo> serviceSet = new ArrayList<WifiP2pServiceInfo>();

    WifiP2pPeer() {
        resetLastSeen();
    }

    public void resetLastSeen() {
        lastSeen = System.nanoTime();
    }

    public long getLastSeen(){
        return lastSeen;
    }

    public int getAckNumber() {
        return ackNumber;
    }

    public void updateSequence(int ackReceived) {
        int bytesAcknowledged = ackReceived - seqNumber;
        sendBuffer.flip();
        sendBuffer.position(bytesAcknowledged);
        sendBuffer.compact();
        seqNumber += bytesAcknowledged;
    }

    public int getSequenceNumber() {
        return seqNumber;
    }

    public void setServiceSet(Collection<WifiP2pServiceInfo> serviceSet) {
        this.serviceSet = serviceSet;
    }

    public Collection<WifiP2pServiceInfo> getServiceSet() {
        return serviceSet;
    }

    public void queuePacket(ByteBuffer packet) {
        sendBuffer.putShort((short) packet.remaining());
        sendBuffer.put(packet);
        Log.d(TAG, "Send Buffer: " + sendBuffer.position());
    }

    public byte[] getPostData(int maxPostData) {
        int count = Math.min(maxPostData, sendBuffer.position());
        byte[] postData = new byte[count];

        for (int i = 0; i < count; i++) {
            postData[i] = sendBuffer.get(i);
        }
        return postData;
    }

    public void recvData(int seqNumber, byte[] data) {
        int offset = ackNumber - seqNumber;
        int count = data.length - offset;
        recvBuffer.put(data, offset, count);
        Log.d(TAG, "Receive Buffer: " + recvBuffer.position());
        ackNumber += count;
    }

    public byte[] getPacket() {
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