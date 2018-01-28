module socks5d.client;

import vibe.core.core;
import vibe.core.log;
import vibe.core.net;
import socks5d.packets;


@safe
class Client
{
    enum BUFSIZE = 1024*8;

    protected:
        static uint     id;

        TCPConnection conn;
        TCPConnection targetConn;
        string       authString;
        AuthMethod[] availableMethods = [
            AuthMethod.NOAUTH,
            //AuthMethod.AUTH,
        ];

    public:
        this(TCPConnection conn, uint id)
        {
            this.conn = conn;
            this.id = id;
        }

        void setAuthString(string authString)
        {
            if (authString.length > 1) {
                this.authString = authString;
                availableMethods = [ AuthMethod.NOAUTH ];
            }
        }

        final void run()
        {
            import vibe.core.stream : pipe;

            logDiagnostic("[%d] New client accepted: %s", id, conn.remoteAddress().toString());

            try {
                if (!authenticate()) {
                    conn.close();

                    return;
                }

                if (handshake()) {
                    logDebug("[%d] Handshake OK", id);

                    auto task1 = runTask(&clientToTargetSession);

                    try {
                        pipe(targetConn, conn);
                    } catch (Exception e) {
                        logDebug("[%d] Client closed connection", id);
                    }

                } else {
                    logDebug("[%d] Handshake error", id);
                    conn.close();
                }

            } catch (SocksException e) {
                logError("[%d] Error: %s", id, e.msg);
                conn.close();
            }
        }

    protected:
        void send(P)(ref P packet)
        if (isSocks5OutgoingPacket!P)
        {
            logDebugV("[%d] send: %s", id, packet.printFields);
            packet.send(conn);
        }

        void receive(P)(ref P packet)
        if (isSocks5IncomingPacket!P)
        {
            packet.receive(conn);
            logDebugV("[%d] recv: %s", id, packet.printFields);
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
                logDiagnostic("[%d] No available method to authenticate.", id);
                return false;
            }

            if (packet2.getMethod() == AuthMethod.AUTH) {
                AuthPacket authPacket;
                AuthStatusPacket authStatusPacket;

                receive(authPacket);
                logDebugV("[%d] Client auth with credentials: %s", id, authPacket.getAuthString());

                if (authPacket.getAuthString() == authString) {
                    authStatusPacket.setStatus(AuthStatus.YES);
                    send(authStatusPacket);
                    logDiagnostic("[%d] Client successfully authenticated.", id);

                    return true;
                } else {
                    authStatusPacket.setStatus(AuthStatus.NO);
                    send(authStatusPacket);
                    logDiagnostic("[%d] Client failed to authenticate.", id);

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
                logWarn("[%d] Error: %s", id, e.msg);
                responsePacket.replyCode = e.replyCode;
                send(responsePacket);

                return false;
            }

            logDebugV("[%d] Connecting to %s:%d", id, requestPacket.getHost(), requestPacket.getPort());
            targetConn = connectTCP(requestPacket.getHost(), requestPacket.getPort());

            responsePacket.addressType = AddressType.IPV4;
            responsePacket.setBindAddress(targetConn.localAddress);

            send(responsePacket);

            return true;
        }

        protected void clientToTargetSession()
        {
            import vibe.core.stream : pipe;
            pipe(conn, targetConn);
        }
}
