module socks5d.client;

import vibe.core.core;
import vibe.core.net;
import socks5d.packets;
import socks5d.driver;
import socks5d.factory : f, logger, ConnectionImpl;
import socks5d.server;

class Client
{
    enum BUFSIZE = 1024*8;

    protected:
        uint     id;

        TCPConnection conn;
        TCPConnection targetConn;

        Server        server;
        AuthMethod[]  availableMethods = [ AuthMethod.NOAUTH ];

    public:
        this(TCPConnection conn, uint id, Server server)
        {
            this.conn = conn;
            this.id = id;
            this.server = server;

            if (server.hasAuthItems()) {
                availableMethods = [ AuthMethod.AUTH ];
            }
        }

        final void run()
        {
            logger.diagnostic("[%d] New client accepted: %s", id, conn.remoteAddress().toString());

            try {
                if (!authenticate()) {
                    conn.close();

                    return;
                }

                if (handshake()) {
                    logger.debugN("[%d] Handshake OK", id);

                    auto task1 = runTask((){
                        pipe(conn, targetConn);
                    });
                    pipe(targetConn, conn);

                } else {
                    logger.debugN("[%d] Handshake error", id);
                    conn.close();
                }

            } catch (SocksException e) {
                logger.error("[%d] Error: %s", id, e.msg);
                conn.close();
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
                method: identificationPacket.detectAuthMethod(availableMethods)
            };

            send(packet2);

            if (packet2.getMethod() == AuthMethod.NOTAVAILABLE) {
                logger.diagnostic("[%d] No available method to authenticate.", id);
                return false;
            }

            if (packet2.getMethod() == AuthMethod.AUTH) {
                AuthPacket authPacket;
                AuthStatusPacket authStatusPacket;

                receive(authPacket);
                logger.debugV("[%d] Client auth with credentials: %s:***", id, authPacket.login);

                if (server.authenticate(authPacket.login, authPacket.password)) {
                    authStatusPacket.setStatus(AuthStatus.YES);
                    send(authStatusPacket);
                    logger.diagnostic("[%d] Client successfully authenticated.", id);

                    return true;
                } else {
                    authStatusPacket.setStatus(AuthStatus.NO);
                    send(authStatusPacket);
                    logger.diagnostic("[%d] Client failed to authenticate.", id);

                    return false;
                }
            }

            return true;
        }

        bool handshake()
        {
            RequestPacket requestPacket = { connID: id };
            ResponsePacket responsePacket = { connID: id };

            try {
                receive(requestPacket);
            } catch (RequestException e) {
                logger.warning("[%d] Error: %s", id, e.msg);
                responsePacket.replyCode = e.replyCode;
                send(responsePacket);

                return false;
            }

            logger.debugV("[%d] Connecting to %s:%d", id, requestPacket.getHost(), requestPacket.getPort());
            targetConn = connectTCP(requestPacket.getHost(), requestPacket.getPort());

            responsePacket.addressType = AddressType.IPV4;
            responsePacket.setBindAddress(
                targetConn.localAddress.sockAddrInet4.sin_addr.s_addr,
                targetConn.localAddress.port
            );

            send(responsePacket);

            return true;
        }

        protected void pipe(ref TCPConnection src, ref TCPConnection dst)
        {
            size_t chunk;

            try {
                while (src.waitForData()) {
                    chunk = src.peek().length;
                    debug logger.debugV("Read src chunk %d", chunk);
                    dst.write(src.peek());
                    src.skip(chunk);
                }
            } catch (Exception e) {
                logger.error("[%d] Client closed connection", id);
            }
        }
}
