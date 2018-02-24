module socks5d.client;

import socks5d.packets;
import socks5d.driver;
import socks5d.factory : f, logger, ConnectionImpl;
import socks5d.server;

class Client
{
    import std.socket : InternetAddress;

    protected:
        uint         id;
        Connection   conn;
        Connection   targetConn;

        Server       server;
        AuthMethod[] availableMethods = [ AuthMethod.NOAUTH ];

    public:
        this(Connection conn, uint id, Server server)
        {

            this.id = id;
            this.server = server;
            this.conn = conn;
            targetConn = f.connection();

            if (server.hasAuthItems()) {
                availableMethods = [ AuthMethod.AUTH ];
            }
        }

        final void run()
        {
            logger.debugN("[%d] New client accepted: %s", id, conn.remoteAddress);

            try {
                if (authenticate()) {
                    logger.debugN("[%d] Client successfully authenticated.", id);
                } else {
                    logger.warning("[%d] Client failed to authenticate.", id);
                    conn.close();

                    return;
                }

                if (handshake) {
                    conn.duplexPipe(targetConn, id);
                } else {
                    conn.close();
                }

            } catch (SocksException e) {
                logger.error("Error: %s", e.msg);
                conn.close();
            }
        }

    protected:
        void send(P)(ref P packet)
        if (isSocks5OutgoingPacket!P)
        {
            logger.trace("[%d] <- %s", id, packet.printFields);
            packet.send(conn);
        }

        void receive(P)(ref P packet)
        if (isSocks5IncomingPacket!P)
        {
            packet.receive(conn);
            logger.trace("[%d] -> %s", id, packet.printFields);
        }


        bool authenticate()
        {
            auto identificationPacket = new MethodIdentificationPacket;
            receive(identificationPacket);

            auto packet2 = new MethodSelectionPacket;

            packet2.method = identificationPacket.detectAuthMethod(availableMethods);

            logger.trace("[%d] <- %s", id, packet2.printFields);
            send(packet2);

            if (packet2.method == AuthMethod.NOTAVAILABLE) {
                return false;
            }

            if (packet2.method == AuthMethod.AUTH) {
                auto authPacket = new AuthPacket;
                auto authStatus = new AuthStatusPacket;

                receive(authPacket);
                //logger.trace("[%d] Client auth with credentials: %s:%s", id, authPacket.login, authPacket.password);

                if (server.authenticate(authPacket.login, authPacket.password)) {
                    authStatus.status = 0x00;
                    //logger.trace("[%d] <- %s", id, authStatus.printFields);
                    send(authStatus);

                    return true;
                } else {
                    authStatus.status = 0x01;
                    send(authStatus);

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
                //logger.error("Error: %s", e.msg);
                packet4.rep = e.replyCode;
                //logger.trace("[%d] <- %s", id, packet4.printFields);
                send(packet4);

                return false;
            }

            connectToTarget(requestPacket.getDestinationAddress());

            packet4.atyp = AddressType.IPV4;
            packet4.setBindAddress(
                targetConn.localAddress.addr,
                targetConn.localAddress.port
            );

            //logger.trace("[%d] Local target address: %s", id, targetConn.localAddress.toString());
            //logger.trace("[%d] <- %s", id, packet4.printFields);
            send(packet4);

            return true;
        }

        bool connectToTarget(InternetAddress address)
        body {
            targetConn.connect(address);
            //logger.trace("[%d] Connecting to target %s", id, address.toString());

            return targetConn.connect(address);
        }
/+
        void targetToClientSession(Socket clientSocket, Socket targetSocket)
        {
            auto sset = new SocketSet(2);
            ubyte[1024*8] buffer;
            ptrdiff_t received;

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
                }
            }

            clientSocket.close();
            targetSocket.close();
        } +/
}
