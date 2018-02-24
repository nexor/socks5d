module socks5d.drivers.vibecore;

import socks5d.factory;
import socks5d.driver;
import socks5d.server;
import vibe.core.core;
import vibe.core.net;
import std.socket;
import std.variant;
import std.container.array;

final class VibeCoreApplication : Application
{
    protected:
        Array!Server servers;

    public:
        @nogc
        void addServer(Server server)
        {
            server.id = cast(uint)this.servers.length;
            this.servers ~= server;
        }

        int run()
        {
            foreach (server; servers) {
                logger.diagnostic("Running server %d", server.id);
                server.run();
            }

            return runApplication();
        }

        bool fileExists(string filename)
        {
            import vibe.core.file;

            return filename.existsFile();
        }
}

/** Connection implementation.
*/
class VibeCoreConnection : Connection
{
    @safe:

    private Socket socket;
    private VibeCoreLogger logger;

    this(Socket s = null, Logger logger = null)
    {
        if (s !is null) {
            socket = s;
        } else {
            socket = new TcpSocket;
        }
        this.logger = cast(VibeCoreLogger)logger;
    }

    @trusted
    void setupConnection(Variant driverConn)
    {
        socket = driverConn.get!Socket;
    }

    @property
    InternetAddress localAddress()
    {
        return cast(InternetAddress)socket.localAddress;
    }

    @property
    InternetAddress remoteAddress()
    {
        return cast(InternetAddress)socket.remoteAddress;
    }

    ptrdiff_t send(const(void)[] buf)
    {
        return socket.send(buf);
    }

    ptrdiff_t receive(void[] buf)
    {
        return socket.receive(buf);
    }

    bool connect(InternetAddress address)
    {
        //connectTCP(requestPacket.getHost(), requestPacket.getPort()); 
        socket = new TcpSocket;
        socket.connect(address);

        return socket.isAlive;
    }

    nothrow @nogc
    void close()
    {
        socket.close();
    }

    void duplexPipe(Connection otherConnection, uint clientId)
    in {
        assert(is(otherConnection == VibeCoreConnection), "otherConnection must be an instance of VibeCoreConnection");
    }
    do {
        auto sset = new SocketSet(2);
        ubyte[1024*8] buffer;
        ptrdiff_t     received;

        auto clientSocket = this.socket;
        auto targetSocket = (cast(VibeCoreConnection)otherConnection).socket;

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
                logger.info("[%d] End of data transfer", clientId);
                break;
            }

            if (sset.isSet(clientSocket)) {
                received = clientSocket.receive(buffer);
                if (received == Socket.ERROR) {
                    logger.warning("[%d] Connection error on clientSocket.", clientId);
                    break;
                } else if (received == 0) {
                    logger.info("[%d] Client connection closed.", clientId);
                    break;
                }

                targetSocket.send(buffer[0..received]);

                debug {
                    bytesToTarget += received;
                    if (bytesToTarget >= bytesToTargetLogThreshold) {
                        logger.trace("[%d] <- %d bytes sent to target", clientId, bytesToTarget);
                        bytesToTarget -= bytesToTargetLogThreshold;
                    }
                }
            }

            if (sset.isSet(targetSocket)) {
                received = targetSocket.receive(buffer);
                if (received == Socket.ERROR) {
                    logger.warning("[%d] Connection error on targetSocket.", clientId);
                    break;
                } else if (received == 0) {
                    logger.info("[%d] Target connection closed.", clientId);
                    break;
                }

                clientSocket.send(buffer[0..received]);

                debug {
                    bytesToClient += received;
                    if (bytesToClient >= bytesToClientLogThreshold) {
                        logger.trace("[%d] <- %d bytes sent to client", clientId, bytesToClient);
                        bytesToClient -= bytesToClientLogThreshold;
                    }
                }
            }
        }

        clientSocket.close();
        targetSocket.close();
    }
}

import core.thread : Thread;

/** ConnectionListener implementation
*/
class VibeCoreConnectionListener : ConnectionListener
{
    @safe:

    private:
        TcpSocket socket;
        uint      backlog = 10;
        bool      isListening = false;
        VibeCoreLogger    logger;

    public:
        this(VibeCoreLogger logger = null)
        {
            this.logger = logger;
        }

        /// Listen given address and port
        @trusted
        void listen(string address, ushort port, ConnectionCallback callback)
        {
            socket = bindSocket(address, port, backlog);
            isListening = true;

            while(true) {
                acceptClient(socket, callback);
            }
        }

        void stopListening()
        {
            if (isListening) {
                socket.close();
                isListening = false;
            }
        }

    protected:
        TcpSocket bindSocket(string address, ushort port, uint backlog)
        {
            // listenTCP(item.port, &handleConnection, item.host);
            
            auto socket = new TcpSocket;
            assert(socket.isAlive);
            socket.bind(new InternetAddress(address, port));
            socket.listen(backlog);

            logger.debugN("Listening on %s", socket.localAddress);

            return socket;
        }

        @trusted
        void acceptClient(Socket socket, ConnectionCallback callback)
        {
            auto clientSocket = socket.accept();
            assert(clientSocket.isAlive);
            assert(socket.isAlive);
            auto conn = f.connection(cast(Variant)clientSocket);

            logger.debugV("Accepted connection %s", socket.localAddress);

            new Thread({
                callback(conn);
            }).start();
        }
/*
        nothrow
        void handleConnection(TCPConnection conn)
        {
            import core.atomic : atomicOp;

            try {
                atomicOp!"+="(clientCounter, 1);
                auto client = new Client(conn, clientCounter, this);

                client.run();
            } catch (Exception e) {
                scope (failure) assert(false);
                logger.error("Connection error: %s", e.msg);
            }
        } */
}

final class VibeCoreLogger : Logger
{
    import vibe.core.log;

    @safe @property
    bool level(byte level)
    {
        switch (level) {
            case 0:
                setLogLevel(LogLevel.info);
                break;
            case 1:
                setLogFormat(FileLogger.Format.thread);
                setLogLevel(LogLevel.diagnostic);
                break;
            case 2:
                setLogFormat(FileLogger.Format.thread);
                setLogLevel(LogLevel.debug_);
                break;
            case 3:
                setLogFormat(FileLogger.Format.threadTime, FileLogger.Format.threadTime);
                setLogLevel(LogLevel.debugV);
                break;
            default:
                setLogLevel(LogLevel.info);
                return false;
        }

        return true;
    }

    nothrow: @safe:

    alias trace      = logTrace;
    alias debugV     = logDebugV;
    alias debugN     = logDebug;
    alias info       = logInfo;
    alias diagnostic = logDiagnostic;
    alias warning    = logWarn;
    alias error      = logError;
    alias critical   = logCritical;
    alias fatal      = logFatal;
}
