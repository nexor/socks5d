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

    private:
        TCPConnection conn;
        VibeCoreLogger logger;

    public:
        this(string unusedTmp = null, Logger logger = null)
        {
            if (logger !is null) {
                this.logger = cast(VibeCoreLogger)logger;
            }
        }

        @property
        InternetAddress localAddress()
        {
            return new InternetAddress(conn.localAddress.toAddressString, conn.localAddress.port);
        }

        @property
        InternetAddress remoteAddress()
        {
            return new InternetAddress(conn.remoteAddress.toAddressString, conn.remoteAddress.port);
        }

        @trusted
        ptrdiff_t send(const(void)[] buf)
        {
            conn.write(cast(ubyte[])buf);
            return buf.length;
        }

        @trusted
        ptrdiff_t receive(void[] buf)
        {
            conn.read(cast(ubyte[])buf);

            return buf.length;
        }

        bool connect(InternetAddress address)
        {
            conn = connectTCP(address.addrToString(address.addr), address.port);

            return conn.connected;
        }

        nothrow
        void close()
        {
            conn.close();
        }

        void duplexPipe(Connection otherConnection, uint clientId)
        in {
            assert(is(otherConnection == VibeCoreConnection), "otherConnection must be an instance of VibeCoreConnection");
        }
        do {
            auto task1 = runTask((){
                pipe(this, cast(VibeCoreConnection)otherConnection, clientId);
            });
            pipe(cast(VibeCoreConnection)otherConnection, this, clientId);
        }

    protected:
        void pipe(VibeCoreConnection src, VibeCoreConnection dst, uint clientId)
        {
            size_t chunk;

            try {
                while (src.conn.waitForData()) {
                    chunk = src.conn.peek().length;
                    debug logger.trace("Read src chunk %d", chunk);
                    dst.conn.write(src.conn.peek());
                    src.conn.skip(chunk);
                }
            } catch (Exception e) {
                logger.error("[%d] Client closed connection", clientId);
            }
        }
}

import core.thread : Thread;

/** ConnectionListener implementation
*/
class VibeCoreConnectionListener : ConnectionListener
{
    @safe:

    private:
        TCPListener listener;
        bool      isListening = false;
        VibeCoreLogger    logger;
        ConnectionCallback callback;

    public:
        this(VibeCoreLogger logger = null)
        {
            this.logger = logger;
        }

        /// Listen given address and port
        @trusted
        void listen(string address, ushort port, ConnectionCallback callback)
        {
            this.callback = callback;
            listener = listenTCP(port, &acceptClient, address);
            isListening = true;
        }

        void stopListening()
        {
            if (isListening) {
                listener.stopListening();
                isListening = false;
            }
        }

    protected:
        @trusted
        void acceptClient(TCPConnection vibeConn)
        {
            auto conn = cast(VibeCoreConnection)f.connection();
            conn.conn = vibeConn;

            logger.debugV("Accepted connection %s", conn.localAddress);

            callback(conn);
        }
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
