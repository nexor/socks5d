module socks5d.client;

import core.thread : Thread;
import std.stdio, std.socket, std.conv;
import socks5d.packets;
import std.experimental.logger;

class Client : Thread
{
    protected:
        uint         id;
        Socket       socket;
        Socket		 targetSocket;
        string       authString;
        AuthMethod[] availableMethods = [ AuthMethod.NOAUTH ];

    public:
        this(Socket clientSocket, uint id)
        {
            socket = clientSocket;
            this.id = id;
            super(&run);
        }

        void setAuthString(string authString)
        {
            if (authString.length > 1) {
                this.authString = authString;
                availableMethods = [ AuthMethod.AUTH ];
            }
        }

        final void run()
        {
            warningf("[%d] New client accepted: %s", id, socket.remoteAddress().toString());



            try {
                if (authenticate()) {
                    infof("[%d] Client successfully authenticated.", id);
                } else {
                    warningf("[%d] Client failed to authenticate.", id);
                    socket.close();

                    return;
                }

                if (handshake) {
                    targetToClientSession(socket, targetSocket);
                } else {
                    socket.close();
                }

            } catch (SocksException e) {
                errorf("Error: %s", e.msg);
                socket.close();

                return;
            }
        }

    protected:
        bool authenticate()
        {
            MethodIdentificationPacket packet;
            packet.receive(socket);
            tracef("[%d] -> %s", id, packet.printFields);

            MethodSelectionPacket packet2;

            packet2.method = packet.detectAuthMethod(availableMethods);

            tracef("[%d] <- %s", id, packet2.printFields);
            socket.send((&packet2)[0..1]);

            if (packet2.method == AuthMethod.NOTAVAILABLE) {
                return false;
            }

            if (packet2.method == AuthMethod.AUTH) {
                AuthPacket authPacket;
                AuthStatusPacket authStatus;

                authPacket.receive(socket);
                tracef("[%d] -> %s", id, authPacket.printFields);
                tracef("[%d] Client auth with credentials: %s", id, authPacket.getAuthString());

                if (authPacket.getAuthString() == authString) {
                    authStatus.status = 0x00;
                    tracef("[%d] <- %s", id, authStatus.printFields);
                    socket.send((&authStatus)[0..1]);

                    return true;
                } else {
                    authStatus.status = 0x01;
                    socket.send((&authStatus)[0..1]);

                    return false;
                }
            }

            return true;
        }

        bool handshake()
        {
            RequestPacket   requestPacket;
            ResponsePacket  packet4;
            InternetAddress targetAddress;

            try {
                targetAddress = requestPacket.receive(socket);
            } catch (RequestException e) {
                errorf("Error: %s", e.msg);
                packet4.rep = e.replyCode;
                tracef("[%d] <- %s", id, packet4.printFields);
                socket.send((&packet4)[0..1]);

                return false;
            }

            tracef("[%d] -> %s", id, requestPacket.printFields);

            targetSocket = connectToTarget(targetAddress);

            packet4.atyp = AddressType.IPV4;
            packet4.setBindAddress(targetSocket.localAddress);

            tracef("[%d] Local target address: %s", id, targetSocket.localAddress.toString());
            tracef("[%d] <- %s", id, packet4.printFields);
            socket.send((&packet4)[0..1]);

            return true;
        }

        Socket connectToTarget(InternetAddress address)
        {
            auto targetSock = new TcpSocket;
            tracef("[%d] Connecting to target %s", id, address.toString());
            targetSock.connect(address);
            assert(targetSock.isAlive);

            return targetSock;
        }

        void targetToClientSession(Socket clientSocket, Socket targetSocket)
        {
            auto sset = new SocketSet(2);
            ubyte[1024*8] buffer;
            ptrdiff_t received;
            int bytesToClient;
            int bytesToClientLogThreshold = 1024*128;
            int bytesToTarget;
            int bytesToTargetLogThreshold = 1024*8;

            for (;; sset.reset()) {
                sset.add(clientSocket);
                sset.add(targetSocket);

                if (Socket.select(sset, null, null) <= 0) {
                    infof("[%d] End of data transfer", id);
                    break;
                }

                if (sset.isSet(clientSocket)) {
                    received = clientSocket.receive(buffer);
                    if (received == Socket.ERROR) {
                        warningf("[%d] Connection error on clientSocket.", id);
                        break;
                    } else if (received == 0) {
                        infof("[%d] Client connection closed.", id);
                        break;
                    }

                    targetSocket.send(buffer[0..received]);
                    debug {
                        bytesToTarget += received;
                        if (bytesToTarget >= bytesToTargetLogThreshold) {
                            tracef("[%d] <- %d bytes sent to target", id, bytesToTarget);
                            bytesToTarget -= bytesToTargetLogThreshold;
                        }
                    }
                }

                if (sset.isSet(targetSocket)) {
                    received = targetSocket.receive(buffer);
                    if (received == Socket.ERROR) {
                        warningf("[%d] Connection error on targetSocket.", id);
                        break;
                    } else if (received == 0) {
                        infof("[%d] Target connection closed.", id);
                        break;
                    }

                    clientSocket.send(buffer[0..received]);

                    bytesToClient += received;
                    if (bytesToClient >= bytesToClientLogThreshold) {
                        tracef("[%d] <- %d bytes sent to client", id, bytesToClient);
                        bytesToClient -= bytesToClientLogThreshold;
                    }
                }

                Thread.yield();
            }

            clientSocket.close();
            targetSocket.close();
        }
}
