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
            logger.diagnostic("[%d] New client accepted: %s", id, conn.remoteAddress);

            try {
                if (!authenticate()) {
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
            logger.debugV("[%d] <- %s", id, packet.printFields);
            packet.send(conn);
        }

        void receive(P)(ref P packet)
        if (isSocks5IncomingPacket!P)
        {
            packet.receive(conn);
            logger.debugV("[%d] -> %s", id, packet.printFields);
        }

        bool authenticate()
        {
            MethodIdentificationPacket identificationPacket = {
                connID: id,
            };
            receive(identificationPacket);

            MethodSelectionPacket packet2 = {
                connID: id,
                method: identificationPacket.detectAuthMethod(availableMethods)
            };

            send(packet2);

            if (packet2.method == AuthMethod.NOTAVAILABLE) {
                return false;
            }

            if (packet2.method == AuthMethod.AUTH) {
                AuthPacket authPacket = {
                    connID : id,
                };
                AuthStatusPacket authStatus;

                receive(authPacket);
                logger.trace("[%d] Client auth with credentials: %s:%s", id, authPacket.login, authPacket.password);

                if (server.authenticate(authPacket.login, authPacket.password)) {
                    authStatus.status = 0x00;
                    logger.trace("[%d] <- %s", id, authStatus.printFields);
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
            RequestPacket requestPacket = { connID: id };
            ResponsePacket packet4 = { connID: id };

            InternetAddress targetAddress;

            try {
                receive(requestPacket);
            } catch (RequestException e) {
                logger.error("Error: %s", e.msg);
                packet4.rep = e.replyCode;
                send(packet4);

                return false;
            }

            connectToTarget(requestPacket.getDestinationAddress());

            packet4.atyp = AddressType.IPV4;
            packet4.setBindAddress(
                targetConn.localAddress.addr,
                targetConn.localAddress.port
            );

            logger.trace("[%d] Local target address: %s", id, targetConn.localAddress);
            send(packet4);

            return true;
        }

        bool connectToTarget(InternetAddress address)
        body {
            targetConn.connect(address);
            logger.trace("[%d] Connecting to target %s", id, address.toString());

            return targetConn.connect(address);
        }
}
