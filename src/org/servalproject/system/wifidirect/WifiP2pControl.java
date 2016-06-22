package org.servalproject.system.wifidirect;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
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
    private final int UNSPECIFIED_ERROR = 500;
    private final int MAX_SERVICE_LENGTH;
    private final int MAX_BINARY_DATA_SIZE;
    private final int MAX_FRAGMENT_LENGTH;
    private final long expiretime = 240000000000L; // 4 min
    private final long checkPeerLostInterval = 10000L; // 10 sec
    // TODO: Find best value for these intervals
    private final int MAX_SERVICE_DISCOVERY_INTERVAL = 15000; // in milliseconds
    private final int MIN_SERVICE_DISCOVERY_INTERVAL = 10000; // in milliseconds
    private final boolean LEGACY_DEVICE;

    private WifiP2pControl(ChannelSelector selector, int loopbackMdpPort) throws IOException {
        super(selector, loopbackMdpPort);
        manager = (WifiP2pManager) ServalBatPhoneApplication.context.getSystemService(Context.WIFI_P2P_SERVICE);
        channel = manager.initialize(ServalBatPhoneApplication.context, ServalBatPhoneApplication.context.getMainLooper(), null);
        localSID = generateRandomHexString(16);
        LEGACY_DEVICE = (Build.VERSION.SDK_INT < 20);
        MAX_SERVICE_LENGTH = (LEGACY_DEVICE) ? 764 : 948;
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
        int ackNumber=0;
        boolean fault = false;
        String base64data = "";
        String serviceType;
        Collections.sort(services);
        WifiP2pPeer peer = peerMap.get(remoteSID);
        boolean updatePost = false;

        resetServiceDiscoveryTimer();
        // TODO: Check for valid packet structure
        // TODO: Check for changes to sequence or ack between fragments
        for (String service : services) {
            serviceType = service.substring(43,44);

            if (serviceType.equals("X")) {
                //Log.d(TAG,"Data Received: " + remoteSID + "::" + service);
                newSequenceNumber = Integer.valueOf(service.substring(19, 23), 16);
                ackNumber = Integer.valueOf(service.substring(9, 13), 16);
                if (sequenceNumber == -1 || sequenceNumber == newSequenceNumber) {
                    sequenceNumber = newSequenceNumber;
                    base64data += service.substring(44);
                } else {
                    Log.e(TAG, "Discarding Malformed Data");
                    fault = true;
                }
            }
        }

        if (!fault) {
            Log.d(TAG,"Data Received from: " + remoteSID
                    + ", Ack: " + ackNumber
                    + ", Seq: " + sequenceNumber
                    + ", Data: " + base64data);
            if (base64data.length() != 0 && sequenceNumber == peerMap.get(remoteSID).getAckNumber()) {
                Log.d(TAG, "New Sequence Received (" + sequenceNumber + ") from " + remoteSID);
                byte[] bytes = Base64.decode(base64data, Base64.DEFAULT);
                try {
                    receivedPacket(hexStringToBytes(remoteSID), bytes);
                    peerMap.get(remoteSID).incrementAckNumber();
                    updatePost = true;
                } catch (IOException e) {
                    Log.e(TAG, e.getMessage(), e);
                }
            }

            if (ackNumber == peer.getCurrentSequenceNumber() + 1) {
                Log.d(TAG, "New Ack Received (" + ackNumber + ") from " + remoteSID);
                peer.removePacket();
                updatePost = true;
            }

            if (updatePost) {
                postPacket(remoteSID);
            }
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
        String query = String.format(Locale.ENGLISH, "-%s::X",  localID);
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
                Log.d(TAG,"Local Service Added");
            }

            @Override
            public void onFailure(int reason) {
                Log.d(TAG,"Failed to Add Local Service!");
            }
        });
    }

    private void queueData(byte[] bytes, String remoteSID) {
        WifiP2pPeer peer = peerMap.get(remoteSID);
        boolean updatePost = !peer.isNextPacket();
        peer.addPacket(bytes);
        if (updatePost) { postPacket(remoteSID); }
    }

    private void postPacket(String remoteSID) {
        byte[] packet = peerMap.get(remoteSID).getPacket();
        int totalBytes = packet.length;
        boolean lastChunk = false;
        String sData;
        int start = 0;
        int end = MAX_BINARY_DATA_SIZE;

        while (!lastChunk) {
            if (end >= totalBytes) {
                end = totalBytes;
                lastChunk = true;
            }
            sData = Base64.encodeToString(packet, start, end - start, Base64.NO_WRAP | Base64.NO_PADDING);

            postStringData(sData, remoteSID);

            start += MAX_BINARY_DATA_SIZE;
            end += MAX_BINARY_DATA_SIZE;
        }
    }

    private void postStringData(String sData, String remoteSID) {
        if (sData.length() > MAX_SERVICE_LENGTH) {
            Log.e(TAG,"More String Data Then Can be handled in single sequence");
            System.exit(UNSPECIFIED_ERROR);
        }
        WifiP2pPeer peer = peerMap.get(remoteSID);
        String uuid;
        String ackNum = String.format(Locale.ENGLISH, "%04x", new Integer(peer.getAckNumber()));
        String uuidPrefix = "0000" + ackNum;
        int sequenceNumber = peer.getCurrentSequenceNumber();
        String device = "";
        String uuidSuffix = remoteSID.substring(0,4) + "-" + remoteSID.substring(4);
        String service;
        int fragmentNumber = 0;
        WifiP2pUpnpServiceInfo serviceInfo;
        ArrayList<String> services;
        ArrayList<WifiP2pServiceInfo> serviceInfos = new ArrayList<WifiP2pServiceInfo>();
        int stringLength = sData.length();
        int start = 0;
        int end = MAX_FRAGMENT_LENGTH;
        boolean lastFragment = false;

        removeServiceSet(peer.getServiceSet());

        while (!lastFragment) {
            if (end >= stringLength) { end = stringLength; lastFragment = true; }
            uuid = String.format(Locale.ENGLISH, "%s-%04d-%04x-%s", uuidPrefix, new Integer(fragmentNumber), new Integer(sequenceNumber), uuidSuffix);
            service = sData.substring(start,end);
            services = new ArrayList<String>();
            services.add("X" + service);

            serviceInfo = WifiP2pUpnpServiceInfo.newInstance(uuid, device, services);
            addLocalService(serviceInfo);
            Log.d(TAG,"Adding Service Info: " + uuid + "::X" + service);
            serviceInfos.add(serviceInfo);

            start += MAX_FRAGMENT_LENGTH;
            end += MAX_FRAGMENT_LENGTH;
        }

        peer.setServiceSet(serviceInfos);
    }

    private void sendBroadcast(byte[] bytes) {
        for (String key : peerMap.keySet()) {
            queueData(bytes, key);
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
                Log.d(TAG,"Local Service removed");
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

    public void write(){
        Log.d(TAG,"Wifi-P2P: Write");
    };
    public void accept(){
        Log.d(TAG,"Wifi-P2P: Accept");
    };
    public void connect(){
        Log.d(TAG,"Wifi-P2P: Connect");
    };

    public void up() {
        Log.d(TAG,"Wifi-P2P: UP");
        state = NetworkState.Enabling;
        setDeviceName("SERVAL" + localSID);
        startDeviceDiscovery();
        checkLostPeers();
        ServalBatPhoneApplication.context.registerReceiver(receiver,intentFilter);
        addServiceRequest();
        setServiceDiscoveryTimer();
        config();
        state = NetworkState.Enabled;
    }

    public void config() {
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
                    .append("broadcast.reachable_timeout_ms=180000\n")
                    .append("broadcast.transmit_timeout_ms=15000\n")
                    .append("broadcast.route=off\n")
                    .append("broadcast.mtu=210\n")
                    .append("broadcast.packet_interval=5000000\n")
                    .append("unicast.tick_ms=5000\n")
                    .append("unicast.reachable_timeout_ms=15000\n")
                    .append("idle_tick_ms=120000\n");
            up(sb.toString());
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
        Log.d(TAG,"Wifi-P2P: getState (" + state.toString() + ")");
        return state;
    }

    @Override
    public void sendPacket(byte[] remoteAddress, ByteBuffer buffer) {
        byte[] data = buffer.array();
        if (data.length > MAX_SERVICE_LENGTH) {
            Log.e(TAG,"Discarding Oversized Packet (" + data.length + ")");
        } else if (remoteAddress == null || remoteAddress.length == 0) {
            Log.d(TAG,"Wifi-P2P: Sending Broadcast Packet");
            sendBroadcast(data);
        } else {
            String hexRemoteAddress = bytesToHexString(remoteAddress);
            if (peerMap.containsKey(hexRemoteAddress)) {
                Log.d(TAG,"Wifi-P2P: Sending Packet to " + hexRemoteAddress);
                queueData(data, hexRemoteAddress);
            } else {
                Log.w(TAG,"Discarding Data To Unknown Address: " + hexRemoteAddress);
            }
        }
    }

    @Override
    public SelectableChannel getChannel() throws IOException {
        Log.d(TAG,"Wifi-P2P: getChannel");
        return socket.getChannel();
    }

    @Override
    public int getInterest() {
        Log.d(TAG,"Wifi-P2P: getInterest");
        return SelectionKey.OP_READ;
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

        for (WifiP2pDevice peer : peers) {
            if (peer.deviceName.matches("SERVAL[[0-9][a-f]]{16}")) {
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
