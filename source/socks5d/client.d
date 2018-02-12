module socks5d.client;

import std.socket;
import socks5d.packets;
import socks5d.connection;
import socks5d.server;
import std.experimental.logger;

class Client
{
    protected:
        uint         id;
        Socket       socket;
        TcpSocket	 targetSocket;
        Connection   conn;
        Connection   targetConn;

        Server       server;
        AuthMethod[] availableMethods = [ AuthMethod.NOAUTH ];

    public:
        this(Socket clientSocket, uint id, Server server)
        {
            socket = clientSocket;
            this.id = id;
            this.server = server;
            conn = Connection(socket);
            targetConn = Connection(null);

            if (server.hasAuthItems()) {
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
                    conn.close();

                    return;
                }

                if (handshake) {
                    targetToClientSession(socket, targetSocket);
                } else {
                    conn.close();
                }

            } catch (SocksException e) {
                errorf("Error: %s", e.msg);
                conn.close();
            }
        }

    protected:
        void send(P)(ref P packet)
        if (isSocks5OutgoingPacket!P)
        {
            debug tracef("[%d] <- %s", id, packet.printFields);
            packet.send(conn);
        }

        void receive(P)(ref P packet)
        if (isSocks5IncomingPacket!P)
        {
            packet.receive(conn);
            debug tracef("[%d] -> %s", id, packet.printFields);
        }


        bool authenticate()
        {
            auto identificationPacket = new MethodIdentificationPacket;
            receive(identificationPacket);

            auto packet2 = new MethodSelectionPacket;

            packet2.method = identificationPacket.detectAuthMethod(availableMethods);

            tracef("[%d] <- %s", id, packet2.printFields);
            packet2.send(socket);

            if (packet2.method == AuthMethod.NOTAVAILABLE) {
                return false;
            }

            if (packet2.method == AuthMethod.AUTH) {
                auto authPacket = new AuthPacket;
                auto authStatus = new AuthStatusPacket;

                receive(authPacket);
                tracef("[%d] Client auth with credentials: %s:%s", id, authPacket.login, authPacket.password);

                if (server.authenticate(authPacket.login, authPacket.password)) {
                    authStatus.status = 0x00;
                    tracef("[%d] <- %s", id, authStatus.printFields);
                    authStatus.send(socket);

                    return true;
                } else {
                    authStatus.status = 0x01;
                    authStatus.send(socket);

                    return false;
                }
            }

            return true;
        }

        bool handshake()
        {
            auto requestPacket = new RequestPacket;
            auto packet4 = new ResponsePacket;
            InternetAddress targetAddress;

            try {
                receive(requestPacket);
            } catch (RequestException e) {
                errorf("Error: %s", e.msg);
                packet4.rep = e.replyCode;
                tracef("[%d] <- %s", id, packet4.printFields);
                packet4.send(socket);

                return false;
            }

            targetSocket = connectToTarget(requestPacket.getDestinationAddress());

            packet4.atyp = AddressType.IPV4;
            packet4.setBindAddress(cast(InternetAddress)targetSocket.localAddress);

            tracef("[%d] Local target address: %s", id, targetSocket.localAddress.toString());
            tracef("[%d] <- %s", id, packet4.printFields);
            packet4.send(socket);

            return true;
        }

        TcpSocket connectToTarget(InternetAddress address)
        out (targetSock) {
            assert(targetSock.isAlive);
        } body {
            auto targetSock = new TcpSocket;
            tracef("[%d] Connecting to target %s", id, address.toString());
            targetSock.connect(address);

            return targetSock;
        }

        void targetToClientSession(Socket clientSocket, Socket targetSocket)
        {
            auto sset = new SocketSet(2);
            ubyte[1024*8] buffer;
            ptrdiff_t received;

            debug {
                int bytesToClient;
                static int bytesToClientLogThreshold = 1024*128;
                int bytesToTarget;
                static int bytesToTargetLogThreshold = 1024*8;
            }

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

                    debug {
                        bytesToClient += received;
                        if (bytesToClient >= bytesToClientLogThreshold) {
                            tracef("[%d] <- %d bytes sent to client", id, bytesToClient);
                            bytesToClient -= bytesToClientLogThreshold;
                        }
                    }
                }
            }

            clientSocket.close();
            targetSocket.close();
        }
}
