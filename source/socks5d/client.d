module socks5d.client;

import socks5d.packets;
import socks5d.driver;
import socks5d.factory : f, logger, ConnectionImpl;
import socks5d.server;
import socks5d.auth;

class Client
{
    package:
        uint         id;

    protected:
        Connection   conn;
        AuthManager authManager;

    public:
        this(Connection conn, uint id, AuthManager authManager)
        {
            assert(authManager !is null);

            this.id = id;
            this.authManager = authManager;
            this.conn = conn;
        }

        final void run()
        {
            logger.diagnostic("[%d] New client accepted: %s", id, conn.remoteAddress);
            scope (exit) conn.close();

            try {
                if (authManager.authenticate(this)) {
                    Connection targetConn = handshake();
                    scope (exit) targetConn.close();

                    conn.duplexPipe(targetConn, id);
                }

            } catch (SocksException e) {
                logger.error("Error: %s", e.msg);
            }

            logger.debugN("[%d] End of session", id);
        }

    package:
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
