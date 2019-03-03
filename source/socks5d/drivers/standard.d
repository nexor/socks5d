module socks5d.drivers.standard;

import socks5d.factory;
import socks5d.driver;
import socks5d.server;
import std.socket;
import std.container.array;
import core.thread : Thread;

debug {
    import core.sys.posix.pthread;

    extern(C) int pthread_setname_np(pthread_t, const char*);

    int setCurrentThreadName(string name)
    {

        import std.string;

        int result = pthread_setname_np(pthread_self(), name.toStringz());
        if (result != 0) {
            logger.error("Can't set thread name, error %d", result);
        }

        return result;
    }
}

/** Connection implementation.
*/
class StandardConnection : Connection
{
    @safe:

    private Socket socket;
    private StandardLogger logger;

    this(StandardLogger logger)
    {
        this.logger = logger;
    }

    this(Socket socket)
    {
        this.socket = socket;
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
        socket = new TcpSocket;
        socket.connect(address);

        return socket.isAlive;
    }

    nothrow @nogc
    void close()
    {
        assert(socket !is null);

        socket.close();
    }

    void duplexPipe(Connection otherConnection, uint clientId)
    in {
        assert(is(otherConnection == StandardConnection), "otherConnection must be an instance of StandardConnection");
    }
    do {
        auto sset = new SocketSet(2);

        ubyte[1024*8] buffer;
        ptrdiff_t     received;

        auto clientSocket = this.socket;
        auto targetSocket = (cast(StandardConnection)otherConnection).socket;

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
                logger.debugN("[%d] End of data transfer", clientId);
                break;
            }

            if (sset.isSet(clientSocket)) {
                received = clientSocket.receive(buffer);
                if (received == Socket.ERROR) {
                    logger.warning("[%d] Connection error on clientSocket.", clientId);
                    break;
                } else if (received == 0) {
                    logger.debugN("[%d] Client connection closed.", clientId);
                    break;
                }

                targetSocket.send(buffer[0..received]);

                debug {
                    bytesToTarget += received;
                    if (bytesToTarget >= bytesToTargetLogThreshold) {
                        logger.debugV("[%d] <- %d bytes sent to target", clientId, bytesToTarget);
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
                    logger.debugN("[%d] Target connection closed.", clientId);
                    break;
                }

                clientSocket.send(buffer[0..received]);

                debug {
                    bytesToClient += received;
                    if (bytesToClient >= bytesToClientLogThreshold) {
                        logger.debugV("[%d] <- %d bytes sent to client", clientId, bytesToClient);
                        bytesToClient -= bytesToClientLogThreshold;
                    }
                }
            }
        }
    }
}

final class StandardApplication : Application
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

            return 0;
        }

        bool fileExists(string filename)
        {
            import std.file;

            return filename.exists();
        }
}

/** ConnectionListener implementation
*/
class StandardConnectionListener : ConnectionListener
{
    @safe:

    private:
        TcpSocket socket;
        uint      backlog = 10;
        bool      isListening = false;
        StandardLogger    logger;

    public:
        this(StandardLogger logger = null)
        {
            this.logger = logger;
        }

        /// Listen given address and port
        @trusted
        void listen(string address, ushort port, ConnectionCallback callback)
        {
            import std.conv;

            new Thread({
                debug setCurrentThreadName(address ~ ":" ~ port.to!string);

                socket = bindSocket(address, port, backlog);
                isListening = true;

                while(true) {
                    acceptClient(socket, callback);
                }
            }).start();
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
            auto socket = new TcpSocket;
            assert(socket.isAlive);
            socket.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
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
            auto conn = cast(StandardConnection)f.connection();
            conn.socket = clientSocket;

            logger.debugV("Accepted connection %s", socket.localAddress);

            new Thread({
                debug setCurrentThreadName("Client");
                callback(conn);
            }).start();
        }
}

final class StandardLogger : Logger
{
    import std.experimental.logger;

    @safe @property
    bool level(byte level)
    {
        switch (level) {
            case 0:
                sharedLog.logLevel = LogLevel.info;
                break;
            case 1:
                sharedLog.logLevel = LogLevel.info;
                break;
            case 2:
                sharedLog.logLevel = LogLevel.trace;
                break;
            case 3:
                sharedLog.logLevel = LogLevel.trace;
                break;
            default:
                sharedLog.logLevel = LogLevel.info;
                return false;
        }

        return true;
    }

    nothrow: @safe:

    alias trace      = tracef;
    alias debugV     = tracef;
    alias debugN     = tracef;
    alias info       = infof;
    alias diagnostic = infof;
    alias warning    = warningf;
    alias error      = errorf;
    alias critical   = criticalf;
    alias fatal      = fatalf;
}
