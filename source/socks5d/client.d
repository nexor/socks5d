module socks5d.client;

import core.thread : Thread;
import std.stdio, std.socket, std.conv;
import socks5d.packets;

class Client : Thread
{
    protected:
        Socket       socket;
        Socket		 targetSocket;
        AuthMethod[] availableMethods = [ AuthMethod.NOAUTH ];

    public:
        this(Socket clientSocket)
        {
            socket = clientSocket;
            super(&run);
        }

        final void run()
        {
            debug writefln("Connection from %s established.", socket.remoteAddress().toString());

            if (!authenticate()) {
                socket.close();

                return;
            }

            RequestPacket packet3;
            ResponsePacket packet4;
            InternetAddress targetAddress;

            try {
                targetAddress = packet3.receive(socket);
                packet4.atyp = AddressType.IPV4;
                packet4.rep = ReplyCode.SUCCEEDED;
            } catch (RequestException e) {
                debug writeln("Exception catched: " ~ e.msg);
                packet4.rep = e.replyCode;
                socket.send((&packet4)[0..1]);
                socket.close();

                return;
            }

            debug writefln("-> ver=%d, cmd=%d, rsv=%d, atyp=%d, dstaddr=%s, dstport=%d",
                packet3.ver, packet3.cmd, packet3.rsv, packet3.atyp, packet3.dstaddr, packet3.dstport);

            targetSocket = connectToTarget(targetAddress);
            packet4.setBindAddress(targetSocket.localAddress);

            debug writefln("Local target: %s", targetSocket.localAddress.toAddrString());
            //debug writefln("Local target port: %d",	targetSocket.localAddress.toPortString());
            socket.send((&packet4)[0..1]);

            debug writefln("<-(%d bytes) ver=%d, rep=%d, rsv=%d, atyp=%d, bndaddr=%s, bndport=%d",
                packet4.sizeof,
                packet4.ver, packet4.rep, packet4.rsv, packet4.atyp, packet4.bndaddr, packet4.bndport);

            targetToClientSession(socket, targetSocket);
        }

    bool authenticate()
    {
        MethodIdentificationPacket packet;
        packet.receive(socket);

        debug writefln("-> ver = %d, nmethods = %d", packet.ver, packet.nmethods);
        debug writefln("-> Proposed methods: %s", to!string(packet.methods));

        MethodSelectionPacket packet2;

        packet2.method = packet.detectAuthMethod(availableMethods);

        debug writefln("<- ver = %d, chosen method = %d", packet2.ver, packet2.method);
        socket.send((&packet2)[0..1]);

        if (packet2.method == AuthMethod.NOTAVAILABLE) {
            return false;
        }

        return true;
    }

    Socket connectToTarget(InternetAddress address)
    {
        auto targetSock = new TcpSocket;
        writefln("Connecting to target %s:%d", address.toAddrString(), address.port);
        targetSock.connect(address);
        assert(targetSock.isAlive);

        return targetSock;
    }

    void targetToClientSession(Socket clientSocket, Socket targetSocket)
    {
        auto sset = new SocketSet(2);
        ubyte[1024*8] buffer;
        ptrdiff_t received;
        debug {
            int bytesToClient;
             int bytesToClientLogThreshold = 1024*128;
            int bytesToTarget;
            int bytesToTargetLogThreshold = 1024*8;
        }

        for (;; sset.reset()) {
            sset.add(clientSocket);
            sset.add(targetSocket);

            if (Socket.select(sset, null, null) <= 0) {
                debug writeln("End of data transfer");
                break;
            }

            if (sset.isSet(clientSocket)) {
                received = clientSocket.receive(buffer);
                if (received == Socket.ERROR) {
                    debug writeln("Connection error on clientSocket.");
                    break;
                } else if (received == 0) {
                    debug writeln("Client connection closed.");
                    break;
                }

                targetSocket.send(buffer[0..received]);
                debug {
                    bytesToTarget += received;
                    if (bytesToTarget >= bytesToTargetLogThreshold) {
                        writefln("<- %d bytes sent to target", bytesToTarget);
                        bytesToTarget -= bytesToTargetLogThreshold;
                    }
                }
            }

            if (sset.isSet(targetSocket)) {
                received = targetSocket.receive(buffer);
                if (received == Socket.ERROR) {
                    debug writeln("Connection error on targetSocket.");
                    break;
                } else if (received == 0) {
                    debug writeln("Target connection closed.");
                    break;
                }

                clientSocket.send(buffer[0..received]);
                debug {
                    bytesToClient += received;
                    if (bytesToClient >= bytesToClientLogThreshold) {
                        writefln("<- %d bytes sent to client", bytesToClient);
                        bytesToClient -= bytesToClientLogThreshold;
                    }
                }
            }

            Thread.yield();
        }

        clientSocket.close();
        targetSocket.close();
    }
}
