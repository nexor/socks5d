module socks5d.driver;

import std.socket : InternetAddress;
import std.variant;

/** Connection iunterface
*/
interface Connection
{
    @safe:

    /// Setup connection with internal connection instance
    void setupConnection(Variant driverConn);

    /// Local address
    @property
    InternetAddress localAddress();

    /// Remote address
    @property
    InternetAddress remoteAddress();

    /// Send data
    ptrdiff_t send(const(void)[] buf);

    /// Receive data
    ptrdiff_t receive(void[] buf);

    /// Connect to address
    bool connect(InternetAddress address);

    /// Close connection
    nothrow @nogc
    void close();

    /// perform bi-directional pipe
    void duplexPipe(Connection otherConnection, uint clientId);
}

alias ConnectionCallback = void delegate(Connection);

/** Connection acceptor
*/
interface ConnectionListener
{
    @safe:

    /// Listen given address and port
    void listen(string address, ushort port, ConnectionCallback callback);

    /// Stop listening given address and port
    void stopListening();
}

/** Logger
*/
interface Logger
{
    @safe
    bool level(byte level);

    nothrow: @safe:

    void trace(S, T...)(S fmt, lazy T args);

    void debugV(S, T...)(S fmt, lazy T args);

    void debugN(S, T...)(S fmt, lazy T args);

    void diagnostic(S, T...)(S fmt, lazy T args);

    void info(S, T...)(S fmt, lazy T args);

    void warning(S, T...)(S fmt, lazy T args);

    void error(S, T...)(S fmt, lazy T args);

    void critical(S, T...)(S fmt, lazy T args);

    void fatal(S, T...)(S fmt, lazy T args);
}
