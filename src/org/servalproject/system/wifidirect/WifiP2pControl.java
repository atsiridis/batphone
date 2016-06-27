package org.servalproject.system.wifidirect;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.wifi.WifiManager;
import android.net.wifi.p2p.WifiP2pDevice;
import android.net.wifi.p2p.WifiP2pDeviceList;
import android.net.wifi.p2p.WifiP2pManager;
import android.net.wifi.p2p.WifiP2pManager.ActionListener;
import android.net.wifi.p2p.WifiP2pManager.Channel;
import android.net.wifi.p2p.WifiP2pManager.UpnpServiceResponseListener;
import android.net.wifi.p2p.nsd.WifiP2pServiceInfo;
import android.net.wifi.p2p.nsd.WifiP2pServiceRequest;
import android.net.wifi.p2p.nsd.WifiP2pUpnpServiceInfo;
import android.net.wifi.p2p.nsd.WifiP2pUpnpServiceRequest;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import org.servalproject.ServalBatPhoneApplication;
import org.servalproject.servaldna.ChannelSelector;
import org.servalproject.servaldna.AbstractExternalInterface;
import org.servalproject.system.NetworkState;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

// TODO: Do not conduct network operations on main thread.

public class WifiP2pControl extends AbstractExternalInterface {
    private static final String TAG = "OS3";
    private WifiP2pManager manager;
    private Channel channel;
    private String localSID;
    private Map<String,WifiP2pPeer> peerList = new ConcurrentHashMap<String,WifiP2pPeer>();
    private Timer checkPeerTimer;
    private IntentFilter intentFilter = new IntentFilter();
    private Timer serviceDiscoveryTimer = new Timer();
    private NetworkState state = NetworkState.Disabled;
    private ReentrantLock servicePostLock = new ReentrantLock();
    private final String DEVICE_NAME_PREFIX = "SERVAL"; // Max 6 Characters
    private final String SERVICE_PREFIX = "X"; // Single Character
    private final int MAX_SERVICE_LENGTH;
    private final int MAX_BINARY_DATA_SIZE;
    private final int MAX_FRAGMENT_LENGTH;
    private final long PEER_TIMEOUT = 240000000000L; // 4 min
    private final long CHECK_PEER_INTERVAL = 10000L; // 10 sec
    private final int MAX_SERVICE_DISCOVERY_INTERVAL = 20000; // in milliseconds
    private final int MIN_SERVICE_DISCOVERY_INTERVAL = 15000; // in milliseconds
    private final boolean LEGACY_DEVICE;

    private WifiP2pControl(ChannelSelector selector, int loopbackMdpPort) throws IOException {
        super(selector, loopbackMdpPort);
        LEGACY_DEVICE = (Build.VERSION.SDK_INT < 20);
        MAX_SERVICE_LENGTH = (LEGACY_DEVICE) ? 764 : 932;
        MAX_FRAGMENT_LENGTH = (LEGACY_DEVICE) ? 187 : MAX_SERVICE_LENGTH;
        MAX_BINARY_DATA_SIZE = MAX_SERVICE_LENGTH * 6 / 8; //(due to Base64 Encoding)

        manager = (WifiP2pManager) ServalBatPhoneApplication.context.getSystemService(Context.WIFI_P2P_SERVICE);
        channel = manager.initialize(ServalBatPhoneApplication.context, ServalBatPhoneApplication.context.getMainLooper(), null);
        localSID = generateRandomHexString(16);

        stopDeviceDiscovery();
        clearLocalServices();
        clearServiceRequests();

        intentFilter.addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION);
        intentFilter.addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION);
        intentFilter.addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION);
        intentFilter.addAction(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION);
        intentFilter.addAction(WifiP2pManager.WIFI_P2P_DISCOVERY_CHANGED_ACTION);
        setResponseListener();

        Log.d(TAG,"#### Initialized New WifiP2pControl (" + localSID + ") ####");
    }

    /* Constructor, checks API level before attempting to instantiate a WifiP2p Object */
    public static WifiP2pControl getWifiP2pControl(ChannelSelector selector, int loopbackMdpPort) throws IOException {
        if (Build.VERSION.SDK_INT < 16) {
            Log.e(TAG,"Attempted to Create WiFi-P2P Instance When Not Supported on This Device.");
            return null;
        } else {
            return new WifiP2pControl(selector, loopbackMdpPort);
        }
    }

    /* Defines the method that will be called whenever a response is received. Checks that the
     response is from a peer with correctly formatted name then calls parseResponse. */
    private void setResponseListener() {
        UpnpServiceResponseListener upnpServiceResponseListener = new UpnpServiceResponseListener() {
            @Override
            public void onUpnpServiceAvailable(List<String> uniqueServiceNames, WifiP2pDevice srcDevice) {
                if (srcDevice.deviceName.matches(DEVICE_NAME_PREFIX + "[[0-9][a-f]]{16}")) {
                    parseResponse(uniqueServiceNames, srcDevice.deviceName.substring(6));
                } else {
                    Log.e(TAG,"ERROR: Unexpected Device Name: " + srcDevice.toString());
                }
            }
        };

        manager.setUpnpServiceResponseListener(channel,upnpServiceResponseListener);
        Log.d(TAG, "Initialized UPnP Service Listeners");
    }

    /* Parses response data, adding data to the receive buffer for that peer and updates the
     acknowledgment and sequence numbers. */
    private void parseResponse(List<String> services, String remoteSID) {
        int sequenceNumber = -1;
        int newSequenceNumber;
        int ackNumber = 0;
        boolean fault = false;
        String base64Data = "";
        Collections.sort(services);
        WifiP2pPeer peer = peerList.get(remoteSID);
        boolean updatePost = false;

        resetServiceDiscoveryTimer();
        for (String service : services) {
            //Log.d(TAG,"Raw Data Received: " + remoteSID + "::" + service);
            if (service.substring(43,44).equals(SERVICE_PREFIX)) {

                newSequenceNumber = Integer.valueOf(service.substring(19, 23), 16);
                ackNumber = Integer.valueOf(service.substring(9, 13), 16);
                if (sequenceNumber == -1 || sequenceNumber == newSequenceNumber) {
                    sequenceNumber = newSequenceNumber;
                    base64Data += service.substring(44);
                } else {
                    Log.e(TAG, "Discarding Malformed Data");
                    fault = true;
                }
            }
        }

        if (!fault) {
            byte[] bytes  = Base64.decode(base64Data, Base64.DEFAULT);
            Log.d(TAG,"Data Received from: " + remoteSID
                    + ", Ack: " + ackNumber
                    + ", Seq: " + sequenceNumber
                    + ", Bytes: " + bytes.length
                    + ", Length: " + base64Data.length());
            if (bytes.length + sequenceNumber > peer.getAckNumber()) {
                Log.d(TAG,"\tNew Sequence: " + peer.getAckNumber() + " -> "
                        + (sequenceNumber + bytes.length));
                peer.recvData(sequenceNumber, bytes);
                deliverPackets(remoteSID);
                updatePost = true;
            }
            if (ackNumber > peer.getSequenceNumber()) {
                Log.d(TAG,"\tNew Ack: " + peer.getSequenceNumber() + " -> " + ackNumber);
                peer.updateSequence(ackNumber);
                updatePost = true;
            }
            if (updatePost) {
                updatePost(remoteSID);
            }
        }
    }

    /* Checks if complete packets are in the receive buffer of the peer and delivers them to the
     application. */
    private void deliverPackets(String remoteSID) {
        WifiP2pPeer peer = peerList.get(remoteSID);

        byte[] packet = peer.getPacket();
        while (packet != null) {
            try {
                Log.d(TAG,remoteSID + " -> [" + md5sum(packet) + "](" + packet.length + ")");
                receivedPacket(hexStringToBytes(remoteSID), packet);
            } catch (IOException e) {
                Log.e(TAG, e.getMessage(), e);
            }
            packet = peer.getPacket();
        }
    }

    private void startDeviceDiscovery() {
        manager.discoverPeers(channel, new ActionListener() {
            @Override
            public void onSuccess() {
                Log.d(TAG,"Starting Device Discovery");
            }

            @Override
            public void onFailure(int reason) {
                Log.d(TAG,"Starting Device Discovery Failed (" + reason + ")!");
                startDeviceDiscovery();
            }
        });
    }

    private void stopDeviceDiscovery() {
        manager.stopPeerDiscovery(channel, new ActionListener() {
            @Override
            public void onSuccess() {
                Log.d(TAG,"Stopping Device Discovery");
            }

            @Override
            public void onFailure(int reason) {
                Log.d(TAG,"Stopping Device Discovery Failed (" + reason + ")!");
            }
        });
    }

    /* Starts the process of connecting to peers and retrieving data from their advertised
     services(posts). */
    private void startServiceDiscovery() {
        manager.discoverServices(channel, new ActionListener() {
            @Override
            public void onSuccess() {
                Log.d(TAG,"Starting Service Discovery");
            }

            @Override
            public void onFailure(int reason) {
                Log.d(TAG,"Starting Service Discovery Failed (" + reason + ")!");
            }
        });
    }

    /* Starts service discovery after a random interval. While doing service discover a device
     may not receive requests from other peers, so a random interval is used to keep devices from
     getting into sync. */
    private void setServiceDiscoveryTimer() {
        Random randomGenerator = new Random();
        serviceDiscoveryTimer = new Timer();
        long interval = MIN_SERVICE_DISCOVERY_INTERVAL + randomGenerator.nextInt(MAX_SERVICE_DISCOVERY_INTERVAL-MIN_SERVICE_DISCOVERY_INTERVAL);
        serviceDiscoveryTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                startServiceDiscovery();
                resetServiceDiscoveryTimer();
            }
        }, interval);
    }

    private void resetServiceDiscoveryTimer() {
        serviceDiscoveryTimer.cancel();
        setServiceDiscoveryTimer();
    }

    private void addServiceRequest(WifiP2pServiceRequest serviceRequest) {
        manager.addServiceRequest(channel, serviceRequest, new ActionListener() {
            @Override
            public void onSuccess() {
                //Log.d(TAG, "Service Request Added");
            }

            @Override
            public void onFailure(int reason) {
                Log.d(TAG, "Failed to Add Service Request");
            }
        });
    }

    /* Creates a service request for this device's SID using a service prefix to avoid getting the
     default service entries in the response. This determines what data is retrieved from a peer's
     posts. */
    private void addServiceRequest() {
        String localID  = localSID.substring(0, 4) + "-" + localSID.substring(4);
        String query = String.format(Locale.ENGLISH, "-%s::%s", localID, SERVICE_PREFIX);
        WifiP2pUpnpServiceRequest serviceRequest = WifiP2pUpnpServiceRequest.newInstance(query);
        Log.d(TAG,"Adding Service Request: " + query);
        addServiceRequest(serviceRequest);
    }

    private void clearServiceRequests() {
        manager.clearServiceRequests(channel, new ActionListener() {
            @Override
            public void onSuccess() {
                Log.d(TAG, "Service Requests Cleared");
            }

            @Override
            public void onFailure(int reason) {
                Log.d(TAG, "Failed to Clear Service Requests");
            }
        });
    }

    private void addLocalService(WifiP2pServiceInfo serviceInfo) {
        manager.addLocalService(channel, serviceInfo, new ActionListener() {
            @Override
            public void onSuccess() {
                //Log.d(TAG,"Local Service Added");
            }

            @Override
            public void onFailure(int reason) {
                Log.d(TAG,"Failed to Add Local Service!");
            }
        });
    }

    /* Adds a packet to the peer's sending queue. If the queue is full the packet is dropped */
    private void queuePacket(String remoteSID, ByteBuffer packet) {
        WifiP2pPeer peer = peerList.get(remoteSID);
        if (!peer.isFull()) {
            int count = packet.remaining();
            int offset = packet.position();
            byte[] bytes = new byte[count];
            for (int i = 0; i < count; i++) {
                bytes[i] = packet.get(offset + i);
            }
            Log.d(TAG, remoteSID + " <- [" + md5sum(bytes) + "](" + bytes.length + ")");
            peer.queuePacket(packet);
            updatePost(remoteSID);
        } else {
            Log.d(TAG, "Buffer Full, Discarding Packet");
        }
    }

    /* Gets a series of bytes from the specified peer's send buffer and converts the data to Base64.
     Deletes the old services(posts) for that peer and generates the new services(posts). A lock is
     used to control access to the posts during the update. */
    private void updatePost(String remoteSID) {
        WifiP2pPeer peer = peerList.get(remoteSID);
        byte[] postData = peer.getPostData(MAX_BINARY_DATA_SIZE);
        //Log.d(TAG, "Updating Post(" + postData.length + ") to " + remoteSID);
        String base64Data = Base64.encodeToString(postData, Base64.NO_WRAP | Base64.NO_PADDING);
        String uuid;
        String uuidPrefix = String.format(Locale.ENGLISH, "%08x", peer.getAckNumber());
        String uuidSuffix = remoteSID.substring(0,4) + "-" + remoteSID.substring(4);
        int sequenceNumber = peer.getSequenceNumber();
        String device = "";
        String service;
        int fragmentNumber = 0;
        WifiP2pUpnpServiceInfo serviceInfo;
        ArrayList<String> services;
        ArrayList<WifiP2pServiceInfo> serviceInfos = new ArrayList<WifiP2pServiceInfo>();
        int stringLength = base64Data.length();
        int start = 0;
        int end = MAX_FRAGMENT_LENGTH;
        boolean lastFragment = false;

        servicePostLock.lock();
        Log.d(TAG, "Posting Data For: " + remoteSID
                + ", Ack: " + peer.getAckNumber()
                + ", Seq: " + peer.getSequenceNumber()
                + ", Bytes: " + postData.length
                + ", Length: " + base64Data.length());
        removeServiceSet(peer.getServiceSet());
        while (!lastFragment) {
            if (end >= stringLength) {
                end = stringLength;
                lastFragment = true;
            }
            uuid = String.format(Locale.ENGLISH, "%s-%04d-%04x-%s", uuidPrefix, fragmentNumber++, sequenceNumber, uuidSuffix);
            service = base64Data.substring(start, end);
            services = new ArrayList<String>();
            services.add(SERVICE_PREFIX + service);
            serviceInfo = WifiP2pUpnpServiceInfo.newInstance(uuid, device, services);
            addLocalService(serviceInfo);
            //Log.d(TAG, "Adding Service Info: " + uuid + "::" + SERVICE_PREFIX + service);
            serviceInfos.add(serviceInfo);

            start += MAX_FRAGMENT_LENGTH;
            end += MAX_FRAGMENT_LENGTH;
        }
        peer.setServiceSet(serviceInfos);
        servicePostLock.unlock();
    }

    /* Broadcasts packets by calling queuePacket for each known peer */
    private void sendBroadcast(ByteBuffer bytes) {
        for (String key : peerList.keySet()) {
            queuePacket(key, bytes);
        }
    }

    private void clearLocalServices() {
        manager.clearLocalServices(channel, new ActionListener() {
            @Override
            public void onSuccess() {
                Log.d(TAG,"Local Services Cleared");
            }

            @Override
            public void onFailure(int reason) {
                Log.d(TAG,"Failed to Clear Local Services!");
            }
        });
    }

    /* Removes a collection of services(posts). Used when updating old posts. */
    private void removeServiceSet (Collection<WifiP2pServiceInfo> services){
        for (WifiP2pServiceInfo serviceInfo : services){
            removeLocalService(serviceInfo);
        }
    }

    private void removeLocalService(WifiP2pServiceInfo serviceInfo) {
        manager.removeLocalService(channel, serviceInfo ,new ActionListener() {
            @Override
            public void onSuccess() {
                //Log.d(TAG,"Local Service removed");
            }

            @Override
            public void onFailure(int reason) {
                Log.d(TAG,"Failed to remove Local Service!");
            }
        });
    }

    /* Check that Wifi is enabled and puts channel in a working state */
    public void up() {
        Log.d(TAG,"Wifi-P2P: UP");
        WifiManager wifi = (WifiManager) ServalBatPhoneApplication.context.getSystemService(Context.WIFI_SERVICE);
        if (wifi.isWifiEnabled()){
            state = NetworkState.Enabling;
            setDeviceName(DEVICE_NAME_PREFIX + localSID);
            startDeviceDiscovery();
            checkPeerTimeout();
            ServalBatPhoneApplication.context.registerReceiver(receiver,intentFilter);
            addServiceRequest();
            setServiceDiscoveryTimer();
            config();
            state = NetworkState.Enabled;
        } else {
            Log.e(TAG, "Wifi Disabled, Cannot Enable Wifi P2P");
        }
    }

    /* Sets configuration parameters for the channel */
    private void config() {
        try {
            String sb = "socket_type=EXTERNAL\n" +
                    "prefer_unicast=off\n" +
                    "broadcast.tick_ms=60000\n" +
                    "broadcast.reachable_timeout_ms=360000\n" +
                    "broadcast.transmit_timeout_ms=5000\n" +
                    "broadcast.route=off\n" +
                    "broadcast.mtu=512\n" +
                    "broadcast.packet_interval=20000000\n" +
                    "unicast.tick_ms=120000\n" +
                    "unicast.reachable_timeout_ms=360000\n" +
                    "unicast.packet_interval=20000000\n" +
                    "debug=on\n" +
                    "idle_tick_ms=30000\n";

            up(sb);
        } catch (IOException e) {
            Log.e(TAG, e.getMessage(), e);
        }
    }

    /* Cleanly shuts down the channel. Deletes state information and cancels timers. */
    public void down() {
        Log.d(TAG,"Wifi-P2P: DOWN");
        state = NetworkState.Disabling;
        serviceDiscoveryTimer.cancel();
        clearLocalServices();
        clearServiceRequests();
        peerList.clear();
        ServalBatPhoneApplication.context.unregisterReceiver(receiver);
        stopDeviceDiscovery();
        checkPeerTimer.cancel();
        setDeviceName(Build.MODEL);
        state = NetworkState.Disabled;
    }

    public NetworkState getState() {
        return state;
    }

    /* Receive packet from the application and queue based on destination address. Packets to an
     unknown destinations are dropped. */
    @Override
    public void sendPacket(byte[] remoteAddress, ByteBuffer packet) {
        int length = packet.remaining();
        if (remoteAddress == null || remoteAddress.length == 0) {
            Log.d(TAG,"Wifi-P2P: Sending Broadcast Packet, Bytes: " + length);
            sendBroadcast(packet);
        } else {
            String hexRemoteAddress = bytesToHexString(remoteAddress);
            if (peerList.containsKey(hexRemoteAddress)) {
                Log.d(TAG,"Wifi-P2P: Sending Packet To: " + hexRemoteAddress + ", Bytes: " + length);
                queuePacket(hexRemoteAddress, packet);
            } else {
                Log.w(TAG,"Discarding Data To Unknown Address: " + hexRemoteAddress);
            }
        }
    }

    /* Converts a byte array to a 16 character hexadecimal string. */
    private String bytesToHexString(byte[] bytes) {
        return String.format("%016x", new BigInteger(1,bytes));
    }

    /* Converts a hexadecimal string to a byte array. Returned byte array length is not fixed.
     There may be a leading null byte due to using a signed data type. */
    private byte[] hexStringToBytes(String hexString) {
        return new BigInteger(hexString,16).toByteArray();
    }

    /* Generates a random hexadecimal string of the specified length. Used to generate local SID. */
    private String generateRandomHexString(int length) {
        Random randomGenerator = new Random();
        String hexString = "";
        for (int i = 0; i < length; i++) {
            hexString += Integer.toHexString(randomGenerator.nextInt(16));
        }
        return hexString;
    }

    /* Logs the MD5 sum of the given byte array. Only used for debugging. */
    private String md5sum(byte[] bytes) {
        try {
            MessageDigest digester = MessageDigest.getInstance("MD5");
            return bytesToHexString(digester.digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG,"MD5 Algorithm Unavailable: " + e);
            return "";
        }
    }

    /* Uses reflection to access hidden method setDeviceName. Sets the device name using the
     application prefix and SID. Some devices limited to a maximum of 22 characters. */
    private void setDeviceName(String devName) {
        try {
            Class[] paramTypes = new Class[3];
            paramTypes[0] = Channel.class;
            paramTypes[1] = String.class;
            paramTypes[2] = ActionListener.class;
            Method setDeviceName = manager.getClass().getMethod(
                    "setDeviceName", paramTypes);
            setDeviceName.setAccessible(true);

            Object arglist[] = new Object[3];
            arglist[0] = channel;
            arglist[1] = devName;
            arglist[2] = new ActionListener() {

                @Override
                public void onSuccess() {
                    //Log.d(TAG,"setDeviceName succeeded");
                }

                @Override
                public void onFailure(int reason) {
                    Log.d(TAG,"setDeviceName failed");
                }
            };

            setDeviceName.invoke(manager, arglist);

        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
    }

    /* Checks for valid names for found peers. Resets time out of known peers. Adds a peer
     WifiP2pPeer object for new peers */
    private void updatePeerList(WifiP2pDeviceList devices) {
        Collection<WifiP2pDevice> peers = devices.getDeviceList();
        String remoteSID;
        for (WifiP2pDevice peer : peers) {
            if (peer.deviceName.matches(DEVICE_NAME_PREFIX + "[[0-9][a-f]]{16}")) {
                remoteSID = peer.deviceName.substring(DEVICE_NAME_PREFIX.length());
                if (!peerList.containsKey(remoteSID)) {
                    peerList.put(remoteSID,new WifiP2pPeer());
                    Log.d(TAG,"New Peer Found: " + remoteSID +" (" + peer.deviceAddress + ")");
                } else {
                    peerList.get(remoteSID).resetLastSeen();
                }
            }
        }
    }

    /* Check the last seen time of each known peer to see if it is above the defined threshold.
     Deletes state for timed out peers. */
    private void checkPeerTimeout() {
        //Log.d(TAG,"Checking for lost peers");
        checkPeerTimer = new Timer();
        checkPeerTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                //Log.d(TAG,"Checking for lost peers");
                for(String remoteSID : peerList.keySet()){
                    //Log.d(TAG,"Current time" + System.nanoTime());
                    //Log.d(TAG,"Peer time" + peerList.get(kp).getLastSeen());
                    if ((System.nanoTime() - peerList.get(remoteSID).getLastSeen()) >= PEER_TIMEOUT){
                        Log.d(TAG,"Deleting peer :" + remoteSID);
                        removeServiceSet(peerList.get(remoteSID).getServiceSet());
                        peerList.remove(remoteSID);
                    }
                }
            }
        }, CHECK_PEER_INTERVAL, CHECK_PEER_INTERVAL);
    }

    /* Receives WifiP2p related broadcast intents. Calls updatePeerList when a peer change has been
     detected. Restarts device discovery whenever it stops. */
    private BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override
        public void onReceive (Context context, Intent intent){
            String action = intent.getAction();
            if (WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION.equals(action)) {
                //Log.d(TAG, "INTENT:WIFI_P2P_STATE_CHANGED_ACTION");
                int state = intent.getIntExtra(WifiP2pManager.EXTRA_WIFI_STATE, -1);
                if (state == WifiP2pManager.WIFI_P2P_STATE_ENABLED) {
                    Log.d(TAG, "WiFi P2P Enabled");
                } else if (state == WifiP2pManager.WIFI_P2P_STATE_DISABLED) {
                    Log.d(TAG, "WiFi P2P Disabled");
                }
            } else if (WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION.equals(action)) {
                //Log.d(TAG, "INTENT:WIFI_P2P_PEERS_CHANGED_ACTION");
                manager.requestPeers(channel, new WifiP2pManager.PeerListListener() {
                    @Override
                    public void onPeersAvailable(WifiP2pDeviceList peers) {
                        updatePeerList(peers);
                    }
                });
            } else if (WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION.equals(action)) {
                //Log.d(TAG, "INTENT:WIFI_P2P_THIS_DEVICE_CHANGED_ACTION");
                WifiP2pDevice device = intent.getParcelableExtra(WifiP2pManager.EXTRA_WIFI_P2P_DEVICE);
                //Log.d(TAG, "Local Device: " + device.deviceName + "(" + device.deviceAddress + ")");
            } else if (WifiP2pManager.WIFI_P2P_DISCOVERY_CHANGED_ACTION.equals(action)) {
                //Log.d(TAG, "INTENT:WIFI_P2P_DISCOVERY_CHANGED_ACTION");
                int state = intent.getIntExtra(WifiP2pManager.EXTRA_DISCOVERY_STATE, -1);
                if (state == WifiP2pManager.WIFI_P2P_DISCOVERY_STARTED) {
                    Log.d(TAG, "Device Discovery Has Started");
                } else if (state == WifiP2pManager.WIFI_P2P_DISCOVERY_STOPPED) {
                    Log.d(TAG, "Device Discovery Has Stopped");
                    startDeviceDiscovery();
                }
            }
        }
    };
}
