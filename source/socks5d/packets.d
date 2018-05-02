module socks5d.packets;

import std.bitmanip;
import std.conv;
import std.traits;
import socks5d.driver;
import socks5d.factory : logger;

enum AuthMethod : ubyte {
    NOAUTH = 0x00,
    AUTH = 0x02,
    NOTAVAILABLE = 0xFF
}

enum AuthStatus : ubyte {
    YES = 0x00,
    NO = 0x01,
}

enum RequestCmd : ubyte {
    CONNECT = 0x01,
    BIND = 0x02,
    UDPASSOCIATE = 0x03
}

enum AddressType : ubyte {
    IPV4 = 0x01,
    DOMAIN = 0x03,
    IPV6 = 0x04
}

enum ReplyCode : ubyte {
    SUCCEEDED = 0x00,
    FAILURE = 0x01,
    NOTALLOWED = 0x02,
    NETWORK_UNREACHABLE = 0x03,
    HOST_UNREACHABLE = 0x04,
    CONNECTION_REFUSED = 0x05,
    TTL_EXPIRED = 0x06,
    CMD_NOTSUPPORTED = 0x07,
    ADDR_NOTSUPPORTED = 0x08
}

string printFields(T)(T args)
{
    import std.format : format;

    string result = typeid(T).toString() ~ ": ";
    auto values = args.tupleof;

    size_t max;
    size_t temp;
    foreach (index, value; values) {
        temp = T.tupleof[index].stringof.length;
        if (max < temp) max = temp;
    }
    max += 1;
    foreach (index, value; values) {
        if (T.tupleof[index].stringof == "connID") {
            continue;
        }
        result ~= format("%s=%s ", T.tupleof[index].stringof, value);
    }

    return result;
}

class SocksException : Exception
{
    import std.exception;

    ///
    mixin basicExceptionCtors;
}

class AuthException : Exception
{
    import std.exception;

    ///
    mixin basicExceptionCtors;
}

class RequestException : SocksException
{
    public:
        ReplyCode replyCode;

        this(ReplyCode replyCode, string msg, string file = __FILE__,
         size_t line = __LINE__, Throwable next = null) @safe pure nothrow
        {
            super(msg, file, line, next);
            this.replyCode = replyCode;
        }
}

mixin template Socks5Packet()
{
    uint connID;    // connection ID
}

mixin template Socks5IncomingPacket()
{
    mixin Socks5Packet;

    ubyte[1] ver = [0x05]; //should be 0x05 (or 0x01 for auth)

    ubyte getVersion()
    {
        return ver[0];
    }

    @safe
    void receiveVersion(Connection conn, ubyte requiredVersion = 0x05)
    {
        conn.receive(ver);

        logger.trace("[%d] Received version: %d", connID, ver[0]);

        if (ver[0] != requiredVersion) {
            throw new SocksException("Incorrect protocol version: " ~ ver[0].to!string);
        }
    }

    @safe
    void receiveBuffer(Connection conn, ref ubyte[1] len, ref ubyte[] buf)
    {

        conn.receive(len);

        logger.trace("[%d] Received buffer length: %d", connID, len[0]);

        buf = new ubyte[len[0]];
        conn.receive(buf);
    }
}

mixin template Socks5OutgoingPacket(TPacketFieldsStruct)
{
    mixin Socks5Packet;

    private union
    {
        TPacketFieldsStruct fields;
        ubyte[fields.sizeof] buffer;
    }

    void send(Connection conn)
    {
        conn.send(buffer);
    }
}

enum bool isSocks5IncomingPacket(P) =
    hasMember!(P, "receive");

enum bool isSocks5OutgoingPacket(P) =
    hasMember!(P, "send");

struct MethodIdentificationPacket
{
    mixin Socks5IncomingPacket;

    ubyte[1] nmethods;
    ubyte[]  methods;

    void receive(Connection conn)
    {
        receiveVersion(conn);
        receiveBuffer(conn, nmethods, methods);
    }

    AuthMethod detectAuthMethod(AuthMethod[] availableMethods)
    {
        import std.algorithm;

        foreach (AuthMethod method; availableMethods) {
            if (methods.canFind(method)) {
                return method;
            }
        }

        return AuthMethod.NOTAVAILABLE;
    }

    ubyte getNMethods()
    {
        return nmethods[0];
    }

    unittest
    {
        import std.socket;
        import socks5d.drivers.standard;

        auto packet = new MethodIdentificationPacket;
        auto sp = socketPair();
        Connection conn = new StandardConnection(sp[1]);
        immutable ubyte[] input = [
            0x05,
            0x01,
            AuthMethod.NOAUTH
        ];

        sp[0].send(input);
        packet.receive(conn);

        assert(packet.getVersion() == 5);
        assert(packet.getNMethods() == 1);
        assert(packet.detectAuthMethod([AuthMethod.NOAUTH]) == AuthMethod.NOAUTH);
        assert(packet.detectAuthMethod([AuthMethod.AUTH]) == AuthMethod.NOTAVAILABLE);
    }
}

struct MethodSelectionPacket
{
    private struct MethodSelectionPacketFields
    {
        align(1):

        ubyte      ver    = 0x05;
        AuthMethod method;
    }

    mixin Socks5OutgoingPacket!MethodSelectionPacketFields;

    @property
    AuthMethod method()
    {
        return fields.method;
    }

    @property
    void method(AuthMethod method)
    {
        fields.method = method;
    }
}

struct AuthPacket
{
    mixin Socks5IncomingPacket;

    ubyte[1]  ulen;
    ubyte[]   uname;
    ubyte[1]  plen;
    ubyte[]   passwd;

    void receive(Connection conn)
    {
        receiveVersion(conn, 0x01);
        receiveBuffer(conn, ulen, uname);
        receiveBuffer(conn, plen, passwd);
    }

    @property
    string login()
    {
        return cast(string)uname;
    }

    @property
    string password()
    {
        return cast(string)passwd;
    }

    unittest
    {
        import std.socket;
        import socks5d.drivers.standard;

        auto packet = new AuthPacket;
        auto sp = socketPair();
        Connection conn = new StandardConnection(sp[1]);
        immutable ubyte[] input = [
            0x01,
            5,
            't', 'u', 's', 'e', 'r',
            7,
            't', 'p', 'a', 's', 's', 'w', 'd'
        ];

        sp[0].send(input);
        packet.receive(conn);

        assert(packet.getVersion() == 1);
        assert(packet.login ~ ":" ~ packet.password == "tuser:tpasswd");
    }
}

struct AuthStatusPacket
{
    private struct AuthStatusPacketFields
    {
        align(1):

        ubyte      ver    = 0x05;
        AuthStatus status = AuthStatus.YES;
    }

    mixin Socks5OutgoingPacket!AuthStatusPacketFields;

    @property
    AuthStatus status()
    {
        return fields.status;
    }

    @property
    void status(AuthStatus status)
    {
        fields.status = status;
    }
}

struct RequestPacket
{
    mixin Socks5IncomingPacket;

    import std.socket : InternetAddress;

    RequestCmd[1]  cmd;
    ubyte[1]       rsv;
    AddressType[1] atyp;
    ubyte[]        dstaddr;
    ubyte[2]       dstport;

    private string host;

    // fill structure with data from socket
    void receive(Connection conn)
    {
        receiveVersion(conn);
        readRequestCommand(conn);
        conn.receive(rsv);

        if (rsv[0] != 0x00) {
            throw new RequestException(ReplyCode.FAILURE, "Received incorrect rsv byte");
        }

        readAddressAndPort(conn);
    }

    ushort getPort()
    {
        return dstport.bigEndianToNative!ushort;
    }

    string getHost()
    {
        return host;
    }

    private void readRequestCommand(Connection conn)
    {
        conn.receive(cast(ubyte[1])cmd);

        debug logger.trace("[%d] Received request command: %s", connID, cmd[0]);

        if (cmd[0] != RequestCmd.CONNECT) {
            throw new RequestException(ReplyCode.CMD_NOTSUPPORTED,
                "Only CONNECT method is supported, given " ~ cmd[0].to!string);
        }
    }

    @trusted
    private void readAddressAndPort(Connection conn)
    {
        import std.socket : InternetAddress;

        conn.receive(cast(ubyte[1])atyp);

        switch (atyp[0]) {
            case AddressType.IPV4:
                debug logger.trace("[%d] Address type: IPV4", connID);

                dstaddr = new ubyte[4];
                conn.receive(dstaddr);
                conn.receive(dstport);

                host = InternetAddress.addrToString(dstaddr.read!uint);
                break;

            case AddressType.DOMAIN:
                debug logger.trace("[%d] Adress type: DOMAIN", connID);

                ubyte[1] length;
                receiveBuffer(conn, length, dstaddr);
                conn.receive(dstport);
                host = stringDstaddr();

                logger.debugN("[%d] Request connect to %s", connID, host);
                break;

            case AddressType.IPV6:
                debug logger.trace("[%d] Address type: IPV6", connID);

                throw new RequestException(ReplyCode.ADDR_NOTSUPPORTED, "AddressType=ipv6 is not supported");

            default:
                debug logger.trace("[%d] Address type: UNKNOWN", connID);

                throw new RequestException(ReplyCode.ADDR_NOTSUPPORTED, "Unknown AddressType: " ~ atyp[0]);
        }
    }

    @trusted
    private string stringDstaddr()
    {
        return cast(string)dstaddr;
    }

    /// test IPv4 address type
    unittest
    {
        import std.socket;
        import socks5d.drivers.standard;

        auto packet = new RequestPacket;
        auto sp = socketPair();
        Connection conn = new StandardConnection(sp[1]);
        immutable ubyte[] input = [
            0x05,
            0x01,
            0x00,
            AddressType.IPV4,
            10, 0, 35, 94,
            0x00, 0x50 // port 80
        ];

        sp[0].send(input);
        packet.receive(conn);

        assert(packet.getVersion() == 5);
        assert(packet.getHost() == "10.0.35.94");
        assert(packet.getPort() == 80);
    }

    /// test domain address type - do not resolve host name
    unittest
    {
        import std.socket;
        import socks5d.drivers.standard;

        auto packet = new RequestPacket;
        auto sp = socketPair();
        Connection conn = new StandardConnection(sp[1]);
        immutable ubyte[] input = [
            0x05,
            0x01,
            0x00,
            AddressType.DOMAIN,
            "localhost".length, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
            0x00, 0x50 // port 80
        ];

        sp[0].send(input);
        packet.receive(conn);

        assert(packet.getVersion() == 5);
        assert(packet.getHost() == "localhost");
        assert(packet.getPort() == 80);
    }
}

@safe
struct ResponsePacket
{
    private struct ResponsePacketFields
    {
        align(1):

        ubyte       ver = 0x05;
        ReplyCode   rep = ReplyCode.SUCCEEDED;
        ubyte       rsv = 0x00;
        AddressType atyp;
        ubyte[uint.sizeof]   bndaddr;
        ubyte[ushort.sizeof] bndport;
    }

    mixin Socks5OutgoingPacket!ResponsePacketFields;

    @property
    void replyCode(ReplyCode code)
    {
        fields.rep = code;
    }

    @property
    void addressType(AddressType type)
    {
        fields.atyp = type;
    }

    bool setBindAddress(uint ip4, ushort port)
    {
        fields.bndaddr = ip4.nativeToBigEndian();
        fields.bndport = port.nativeToBigEndian();

        debug {
            import std.socket : InternetAddress;
            auto address = new InternetAddress(ip4, port);
            logger.trace("[%d] Local target address: %s", connID, address.toAddrString());
        }

        return true;
    }

    unittest
    {
        import std.socket;
        import socks5d.drivers.standard;

        auto packet = new ResponsePacket;
        auto address = new InternetAddress("127.0.0.1", 81);
        auto sp = socketPair();
        auto conn = new StandardConnection(sp[0]);
        immutable ubyte[] output = [
            0x05,
            ReplyCode.SUCCEEDED,
            0x00,
            AddressType.IPV4,
            127, 0, 0, 1, // 127.0.0.1
            0x00, 0x51    // port 81
        ];

        packet.setBindAddress(address.addr, address.port);

        packet.send(conn);
        ubyte[output.length] buf;
        sp[1].receive(buf);

        assert(buf == output);
    }
}
