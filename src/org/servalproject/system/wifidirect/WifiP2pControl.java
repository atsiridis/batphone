package org.servalproject.system.wifidirect;

import android.app.Application;
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

import org.servalproject.R;
import org.servalproject.ServalBatPhoneApplication;
import org.servalproject.servaldna.AbstractExternalInterface;
import org.servalproject.servaldna.ChannelSelector;
import org.servalproject.system.NetworkState;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.security.MessageDigest;
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

public class WifiP2pControl extends AbstractExternalInterface {
    private static final String TAG = "OS3";
    private WifiP2pManager manager;
    private Channel channel;
    private String localSID;
    private Map<String,WifiP2pPeer> peerMap = new ConcurrentHashMap<String,WifiP2pPeer>();
    private Timer checkLastSeenPeer;
    private IntentFilter intentFilter = new IntentFilter();
    private Timer serviceDiscoveryTimer = new Timer();
    private NetworkState state = NetworkState.Disabled;
    private ReentrantLock servicePostLock = new ReentrantLock();
    private final String DEVICE_NAME_PREFIX = "SERVAL"; // Max 6 Characters
    private final String SERVICE_PREFIX = "X"; // Single Character
    private final int UNSPECIFIED_ERROR = 500;
    private final int MAX_SERVICE_LENGTH;
    private final int MAX_BINARY_DATA_SIZE;
    private final int MAX_FRAGMENT_LENGTH;
    private final long expiretime = 240000000000L; // 4 min
    private final long checkPeerLostInterval = 10000L; // 10 sec
    // TODO: Find best value for these intervals
    private final int MAX_SERVICE_DISCOVERY_INTERVAL = 20000; // in milliseconds
    private final int MIN_SERVICE_DISCOVERY_INTERVAL = 15000; // in milliseconds
    private final boolean LEGACY_DEVICE;

    private WifiP2pControl(ChannelSelector selector, int loopbackMdpPort) throws IOException {
        super(selector, loopbackMdpPort);
        manager = (WifiP2pManager) ServalBatPhoneApplication.context.getSystemService(Context.WIFI_P2P_SERVICE);
        channel = manager.initialize(ServalBatPhoneApplication.context, ServalBatPhoneApplication.context.getMainLooper(), null);
        localSID = generateRandomHexString(16);
        LEGACY_DEVICE = (Build.VERSION.SDK_INT < 20);
        MAX_SERVICE_LENGTH = (LEGACY_DEVICE) ? 764 : 932;
        MAX_FRAGMENT_LENGTH = (LEGACY_DEVICE) ? 187 : MAX_SERVICE_LENGTH;
        MAX_BINARY_DATA_SIZE = MAX_SERVICE_LENGTH * 6 / 8; //(due to Base64 Encoding)

        stopDeviceDiscovery();
        clearLocalServices();
        clearServiceRequests();

        intentFilter.addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION);
        intentFilter.addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION);
        intentFilter.addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION);
        intentFilter.addAction(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION);
        intentFilter.addAction(WifiP2pManager.WIFI_P2P_DISCOVERY_CHANGED_ACTION);
        setResponseListener();

        Log.d(TAG,"##################### Initialized New WifiP2pControl #####################");
        Log.v(TAG,"manifest_id: " + R.string.manifest_id);
    }

    /* Init */

    private void setResponseListener() {
        UpnpServiceResponseListener upnpServiceResponseListener = new UpnpServiceResponseListener() {
            @Override
            public void onUpnpServiceAvailable(List<String> uniqueServiceNames, WifiP2pDevice srcDevice) {
                if (srcDevice.deviceName.length() != 22) {
                    Log.e(TAG,"ERROR: Unexpected Device Name: " + srcDevice.toString());
                } else {
                    parseResponse(uniqueServiceNames, srcDevice.deviceName.substring(6));
                }
            }
        };

        manager.setUpnpServiceResponseListener(channel,upnpServiceResponseListener);
        Log.d(TAG, "Initialized UPnP Service Listeners");
    }

    /* Receive Data */

    private void parseResponse(List<String> services, String remoteSID) {
        int sequenceNumber = -1;
        int newSequenceNumber;
        int ackNumber = 0;
        boolean fault = false;
        String base64Data = "";
        Collections.sort(services);
        WifiP2pPeer peer = peerMap.get(remoteSID);
        boolean updatePost = false;

        resetServiceDiscoveryTimer();
        // TODO: Check for valid packet structure
        // TODO: Should all fragments have same UUID? (except frag num)
        for (String service : services) {
            //Log.d(TAG,"Data Received: " + remoteSID + "::" + service);
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

    private void deliverPackets(String remoteSID) {
        WifiP2pPeer peer = peerMap.get(remoteSID);

        byte[] packet = peer.getPacket();
        while (packet != null) {
            try {
                Log.d(TAG + "X",remoteSID + " -> [" + md5sum(packet) + "](" + packet.length + ")");
                receivedPacket(hexStringToBytes(remoteSID), packet);
            } catch (IOException e) {
                Log.e(TAG, e.getMessage(), e);
            }
            packet = peer.getPacket();
        }
    }

    /* Control */

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

    /* Service Requests */

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

    /* Local Services */

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

    private void queuePacket(String remoteSID, ByteBuffer packet) {
        WifiP2pPeer peer = peerMap.get(remoteSID);
        int count = packet.remaining();
        int offset = packet.position();
        byte[] bytes = new byte[count];
        for (int i = 0; i < count; i++) {
            bytes[i] = packet.get(offset + i);
        }

        Log.d(TAG + "X",remoteSID + " <- [" + md5sum(bytes) + "](" + bytes.length + ")");
        peer.queuePacket(packet);
        updatePost(remoteSID);
    }

    private void updatePost(String remoteSID) {
        WifiP2pPeer peer = peerMap.get(remoteSID);
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

    private void sendBroadcast(ByteBuffer bytes) {
        for (String key : peerMap.keySet()) {
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

    private void removeServiceSet (Collection<WifiP2pServiceInfo> services){
        for (WifiP2pServiceInfo serviceInfo : services){
            removeLocalService(serviceInfo);
        }
    }

    private void removeLocalService(WifiP2pServiceInfo serviceinfo) {
        manager.removeLocalService(channel, serviceinfo ,new ActionListener() {
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

    /* Interface Implementation */

    public static WifiP2pControl getWifiP2pControl(ChannelSelector selector, int loopbackMdpPort) throws IOException {
        if (Build.VERSION.SDK_INT < 16) {
            Log.e(TAG,"Attempted to Create WiFi-P2P Instance When Not Supported on This Device.");
            return null;
        } else {
            return new WifiP2pControl(selector, loopbackMdpPort);
        }
    }

    public void up() {
        Log.d(TAG,"Wifi-P2P: UP");
        WifiManager wifi = (WifiManager) ServalBatPhoneApplication.context.getSystemService(Context.WIFI_SERVICE);
        if (wifi.isWifiEnabled()){
            state = NetworkState.Enabling;
            setDeviceName(DEVICE_NAME_PREFIX + localSID);
            startDeviceDiscovery();
            checkLostPeers();
            ServalBatPhoneApplication.context.registerReceiver(receiver,intentFilter);
            addServiceRequest();
            setServiceDiscoveryTimer();
            config_bt();
            state = NetworkState.Enabled;
        } else {
            Log.e(TAG, "Cannot Enable WifiP2p, Wifi is Disabled");
        }
    }

    private void config() {
        try {
            StringBuilder sb = new StringBuilder();

            // We model "broadcast" packets using the bluetooth name of this device
            // This can be useful for easily discovering that our software is running

            // However, we have to initiate a scan to read bluetooth names,
            // which massively reduces our available bandwidth

            // We don't really want to know what the connectivity picture looks like.
            // We want our servald daemon to make those decisions.

            // So we assume that setting our name should trigger a device scan in order to detect
            // the name change of other peers. If this is the only link between two devices,
            // servald will probably try to send packets as fast as we allow.

            // And we set the tickms interval to 2 minutes, to force a periodic scan for peer detection.

            // MTU = trunc((248 - 7)/8)*7 = 210
            // on some devices it seems to be (127 - 7)/8*7 = 105

            sb.append("socket_type=EXTERNAL\n")
                    .append("prefer_unicast=on\n")
                    .append("broadcast.tick_ms=120000\n")
                    .append("broadcast.reachable_timeout_ms=240000\n")
                    .append("broadcast.transmit_timeout_ms=240000\n")
                    .append("broadcast.route=off\n")
                    .append("broadcast.mtu=256\n")
                    .append("broadcast.packet_interval=10000000\n")
                    .append("unicast.mtu=256\n")
                    .append("unicast.tick_ms=120000\n")
                    .append("unicast.reachable_timeout_ms=240000\n")
                    .append("unicast.transmit_timeout_ms=240000\n")
                    .append("unicast.packet_interval=10000000\n")
                    .append("idle_tick_ms=30000\n");
            up(sb.toString());
        } catch (IOException e) {
            Log.e(TAG, e.getMessage(), e);
        }
    }

    private void config_bt() {
        try {
            String sb = "socket_type=EXTERNAL\n" +
                    "prefer_unicast=on\n" +
                    "broadcast.tick_ms=120000\n" +
                    "broadcast.reachable_timeout_ms=180000\n" +
                    "broadcast.transmit_timeout_ms=15000\n" +
                    "broadcast.route=off\n" +
                    "broadcast.mtu=210\n" +
                    "broadcast.packet_interval=5000000\n" +
                    "unicast.tick_ms=5000\n" +
                    "unicast.reachable_timeout_ms=15000\n" +
                    "idle_tick_ms=120000\n";

            up(sb);
        } catch (IOException e) {
            Log.e(TAG, e.getMessage(), e);
        }
    }

    public void down() {
        Log.d(TAG,"Wifi-P2P: DOWN");
        state = NetworkState.Disabling;
        serviceDiscoveryTimer.cancel();
        clearLocalServices();
        clearServiceRequests();
        peerMap.clear();
        ServalBatPhoneApplication.context.unregisterReceiver(receiver);
        stopDeviceDiscovery();
        checkLastSeenPeer.cancel();
        setDeviceName(Build.MODEL);
        state = NetworkState.Disabled;
    }

    @Override
    public void close(){
        Log.d(TAG,"Wifi-P2P: Close");
    }

    public NetworkState getState() {
        //Log.d(TAG,"Wifi-P2P: getState (" + state.toString() + ")");
        return state;
    }

    @Override
    public void sendPacket(byte[] remoteAddress, ByteBuffer packet) {
        int length = packet.remaining();
        if (remoteAddress == null || remoteAddress.length == 0) {
            Log.d(TAG,"Wifi-P2P: Sending Broadcast Packet, Bytes: " + length);
            sendBroadcast(packet);
        } else {
            String hexRemoteAddress = bytesToHexString(remoteAddress);
            if (peerMap.containsKey(hexRemoteAddress)) {
                Log.d(TAG,"Wifi-P2P: Sending Packet To: " + hexRemoteAddress + ", Bytes: " + length);
                queuePacket(hexRemoteAddress, packet);
            } else {
                Log.w(TAG,"Discarding Data To Unknown Address: " + hexRemoteAddress);
            }
        }
    }

    /* Util */

    private String bytesToHexString(byte[] bytes) {
        return String.format("%016x", new BigInteger(1,bytes));
    }

    private byte[] hexStringToBytes(String hexString) {
        // NOTE: Returned byte array length is not fixed!
        return new BigInteger(hexString,16).toByteArray();
    }

    private String generateRandomHexString(int length) {
        Random randomGenerator = new Random();
        String hexString = "";
        for (int i = 0; i < length; i++) {
            hexString += Integer.toHexString(randomGenerator.nextInt(16));
        }
        return hexString;
    }

    private String md5sum(byte[] bytes) {
        try {
            MessageDigest digester = MessageDigest.getInstance("MD5");
            return bytesToHexString(digester.digest(bytes));
        } catch (Exception e) {
            Log.wtf(TAG,"Exception: " + e);
            return "";
        }
    }

    /* Reflection */

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

    /* Intent Handling */

    private void updatePeerList(WifiP2pDeviceList devices) {
        Collection<WifiP2pDevice> peers = devices.getDeviceList();
        String remoteSID;
        int wifiPeers = peers.size();
        int servalPeers = 0;
        for (WifiP2pDevice peer : peers) {
            if (peer.deviceName.matches(DEVICE_NAME_PREFIX + "[[0-9][a-f]]{16}")) {
                servalPeers++;
                remoteSID = peer.deviceName.substring(6);
                if (!peerMap.containsKey(remoteSID)) {
                    peerMap.put(remoteSID,new WifiP2pPeer());
                    Log.d(TAG,"New Peer Found: " + remoteSID +" (" + peer.deviceAddress + ")");
                    try {
                        receivedPacket(hexStringToBytes(remoteSID), new byte[0]);
                    } catch (Exception e) {
                        Log.e(TAG, "Packet Error");
                    }
                } else {
                    peerMap.get(remoteSID).resetLastSeen();
                }
                Log.d(TAG, "Serval Peers: " + servalPeers + "/" + wifiPeers + "/" + peerMap.size());
            }
        }
    }

    private void checkLostPeers() {
        //Log.d(TAG,"Checking for lost peers");
        checkLastSeenPeer = new Timer();
        checkLastSeenPeer.schedule(new TimerTask() {
            @Override
            public void run() {
                //Log.d(TAG,"Checking for lost peers");
                for(String kp : peerMap.keySet()){
                    //Log.d(TAG,"Current time" + System.nanoTime());
                    //Log.d(TAG,"Peer time" + peerMap.get(kp).getLastSeen());
                    if ((System.nanoTime() - peerMap.get(kp).getLastSeen()) >= expiretime){
                        Log.d(TAG,"Deleting peer :" + kp);
                        //This can stay as it is it will not introduce errors but we have to decide
                        removeServiceSet(peerMap.get(kp).getServiceSet());
                        peerMap.remove(kp);
                    }
                }
            }
        },checkPeerLostInterval,checkPeerLostInterval);
    }

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
