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
        AuthMethod[] availableMethods = [ AuthMethod.NoAUTH ];

    public:
        this(Socket clientSocket, uint id)
        {
            socket = clientSocket;
            this.id = id;
            super(&run);
        }

        final void run()
        {
            warningf("[%d] New client accepted: %s:%s", id,
                socket.remoteAddress().toAddrString(),
                socket.remoteAddress().toPortString()
            );

            try {
                if (!authenticate()) {
                    warningf("[%d] Client failed to authenticate.", id);
                    socket.close();

                    return;
                }


                infof("[%d] Client successfully authenticated.", id);


                RequestPacket packet3;
                ResponsePacket packet4;
                InternetAddress targetAddress;

                try {
                    targetAddress = packet3.receive(socket);
                    tracef("[%d] -> ver=%d, cmd=%d, rsv=%d, atyp=%d, dstaddr=%s, dstport=%d", id,
                        packet3.ver, packet3.cmd, packet3.rsv, packet3.atyp, packet3.dstAddressString(),
                        packet3.dstport
                    );
                    tracef("[%d] Target address detected: %s:%s", id,
                        targetAddress.toAddrString(),
                        targetAddress.toPortString(),
                    );
                    packet4.atyp = AddressType.IPV4;
                    packet4.rep = ReplyCode.SUCCEEDED;
                } catch (RequestException e) {
                    errorf("Error: %s", e.msg);
                    packet4.rep = e.replyCode;
                    socket.send((&packet4)[0..1]);

                    throw e;
                }


                targetSocket = connectToTarget(targetAddress);
                packet4.setBindAddress(targetSocket.localAddress);

                tracef("[%d] Local target address: %s:%s", id,
                    targetSocket.localAddress.toAddrString(),
                    targetSocket.localAddress.toPortString(),
                );
                socket.send((&packet4)[0..1]);

                tracef("[%d] <-(%d bytes) ver=%d, rep=%d, rsv=%d, atyp=%d, bndaddr=%s, bndport=%d", id,
                    packet4.sizeof,
                    packet4.ver, packet4.rep, packet4.rsv, packet4.atyp, packet4.bndaddr, packet4.bndport);

            } catch (SocksException e) {
                errorf("Auth error: %s", e.msg);
                socket.close();

                return;
            }

            targetToClientSession(socket, targetSocket);
        }

    bool authenticate()
    {
        MethodIdentificationPacket packet;
        packet.receive(socket);

        tracef("[%d] -> ver = %d, nmethods = %d", id, packet.ver, packet.nmethods);
        tracef("[%d] -> Proposed methods: %s", id, to!string(packet.methods));

        MethodSelectionPacket packet2;

        packet2.method = packet.detectAuthMethod(availableMethods);

        tracef("[%d] <- ver = %d, chosen method = %d", id, packet2.ver, packet2.method);
        socket.send((&packet2)[0..1]);

        if (packet2.method == AuthMethod.NOTAVAILABLE) {
            return false;
        }

        if (packet2.method == AuthMethod.AUTH) {
            AuthPacket authPacket;
            AuthStatusPacket authStatus;

            authPacket.receive(socket);
            tracef("[%d] -> ver = %d, ulen=%d, uname=%s, plen=%d, passwd=%s", id,
                authPacket.ver, authPacket.ulen, authPacket.uname, authPacket.plen,
                authPacket.passwd
            );
            tracef("[%d] Client auth with credentials: %s:%s", id,
                authPacket.getUsername(), authPacket.getPassword()
            );

            if (authPacket.getUsername() == "username" && authPacket.getPassword() == "1234") {
                authStatus.status = 0x00;
                socket.send((&authStatus)[0..1]);
                tracef("[%d] (%d) <- ver = %d, status=%d", id,
                    authStatus.sizeof, authStatus.ver, authStatus.status
                );

                return true;
            } else {
                authStatus.status = 0x01;
                socket.send((&authStatus)[0..1]);

                return false;
            }
        }

        return true;
    }

    Socket connectToTarget(InternetAddress address)
    {
        auto targetSock = new TcpSocket;
        tracef("[%d] Connecting to target %s:%d", id, address.toAddrString(), address.port);
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
