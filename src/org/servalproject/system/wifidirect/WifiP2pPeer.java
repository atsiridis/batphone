package org.servalproject.system.wifidirect;

import android.net.wifi.p2p.nsd.WifiP2pServiceInfo;
import android.util.Log;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.ConcurrentLinkedQueue;

public class WifiP2pPeer {
    private int seqNumber = 0;
    private int ackNumber = 0;
    private long lastSeen;
    private ConcurrentLinkedQueue<byte[]> packetQueue = new ConcurrentLinkedQueue<byte[]>();
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

    public void incrementAckNumber() {
        ackNumber++;
    }

    public int getCurrentSequenceNumber() {
        return seqNumber;
    }

    public void addPacket(byte[] packet) {
        packetQueue.add(packet);
        Log.d("OS3","Packet Added to Queue, " + packetQueue.size() + " pending");
    }

    public byte[] getPacket() {
        if (packetQueue.isEmpty()) {
            return new byte[0];
        } else {
            return packetQueue.peek();
        }
    }

    public boolean isNextPacket() {
        return !packetQueue.isEmpty();
    }

    public byte[] removePacket() {
        if (packetQueue.isEmpty()) {
            return new byte[0];
        } else {
            seqNumber++;
            return packetQueue.remove();
        }
    }

    public void setServiceSet(Collection<WifiP2pServiceInfo> serviceSet) {
        this.serviceSet = serviceSet;
    }

    public Collection<WifiP2pServiceInfo> getServiceSet() {
        return serviceSet;
    }

}
