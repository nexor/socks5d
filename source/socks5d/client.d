module socks5d.client;

import socks5d.packets;
import socks5d.driver;
import socks5d.factory : f, logger, ConnectionImpl;
import socks5d.server;

class Client
{
    protected:
        uint         id;
        Connection   conn;

        Server       server;
        AuthMethod[] availableMethods = [ AuthMethod.NOAUTH ];

    public:
        this(Connection conn, uint id, Server server)
        {

            this.id = id;
            this.server = server;
            this.conn = conn;

            if (server.hasAuthItems()) {
                availableMethods = [ AuthMethod.AUTH ];
            }
        }

        final void run()
        {
            logger.diagnostic("[%d] New client accepted: %s", id, conn.remoteAddress);
            scope (exit) conn.close();

            try {
                if (authenticate()) {
                    Connection targetConn = handshake();
                    scope (exit) targetConn.close();

                    conn.duplexPipe(targetConn, id);
                }

            } catch (SocksException e) {
                logger.error("Error: %s", e.msg);
            }

            logger.debugN("[%d] End of session", id);
        }

    protected:
        void send(P)(ref P packet)
        if (isSocks5OutgoingPacket!P)
        {
            logger.debugV("[%d] send: %s", id, packet.printFields);
            packet.send(conn);
        }

        void receive(P)(ref P packet)
        if (isSocks5IncomingPacket!P)
        {
            packet.receive(conn);
            logger.debugV("[%d] recv: %s", id, packet.printFields);
        }

        bool authenticate()
        {
            MethodIdentificationPacket identificationPacket = {
                connID: id,
            };
            receive(identificationPacket);

            MethodSelectionPacket packet2 = {
                connID: id,
            };
            packet2.method = identificationPacket.detectAuthMethod(availableMethods);

            send(packet2);

            if (packet2.method == AuthMethod.NOTAVAILABLE) {
                logger.diagnostic("[%d] No available method to authenticate.", id);
                return false;
            }

            if (packet2.method == AuthMethod.AUTH) {
                AuthPacket authPacket;
                AuthStatusPacket authStatusPacket;

                receive(authPacket);
                logger.debugV("[%d] Client auth with credentials: %s:***", id, authPacket.login);

                if (server.authenticate(authPacket.login, authPacket.password)) {
                    authStatusPacket.status = AuthStatus.YES;
                    send(authStatusPacket);
                    logger.diagnostic("[%d] Client successfully authenticated.", id);

                    return true;
                } else {
                    authStatusPacket.status = AuthStatus.NO;
                    send(authStatusPacket);
                    logger.diagnostic("[%d] Client failed to authenticate.", id);

                    return false;
                }
            }

            return true;
        }

        Connection handshake()
        {
            import std.socket : InternetAddress;

            RequestPacket requestPacket = { connID: id };
            ResponsePacket responsePacket = { connID: id };

            try {
                receive(requestPacket);
            } catch (RequestException e) {
                logger.warning("[%d] Error: %s", id, e.msg);
                responsePacket.replyCode = e.replyCode;
                send(responsePacket);

                throw e;
            }

            logger.debugV("[%d] Connecting to %s:%d", id, requestPacket.getHost(), requestPacket.getPort());

            Connection targetConn = f.connection();
            targetConn.connect(new InternetAddress(requestPacket.getHost(), requestPacket.getPort()));

            responsePacket.addressType = AddressType.IPV4;
            responsePacket.setBindAddress(
                targetConn.localAddress.addr,
                targetConn.localAddress.port
            );

            send(responsePacket);

            return targetConn;
        }
}
