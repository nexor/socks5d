module socks5d.packets;

import std.socket;
import std.bitmanip;
import std.conv;
import std.traits;
import vibe.core.net;
import vibe.core.log;

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
    public:

        this(string msg, string file = __FILE__,
         size_t line = __LINE__, Throwable next = null) @safe pure nothrow
        {
            super(msg, file, line, next);
        }
}

class AuthException : Exception
{
    public:

        this(string msg, string file = __FILE__,
         size_t line = __LINE__, Throwable next = null) @safe pure nothrow
        {
            super(msg, file, line, next);
        }
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
    ubyte[1] ver = [0x05]; //should be 0x05 (or 0x01 for auth)
    uint connID;    // connection ID

    ubyte getVersion()
    {
        return ver[0];
    }
}

mixin template Socks5IncomingPacket()
{
    mixin Socks5Packet;

    @safe
    void receiveVersion(TCPConnection conn, ubyte requiredVersion = 0x05)
    {
        conn.read(ver);

        logTrace("[%d] Received version: %d", connID, ver[0]);

        if (ver[0] != requiredVersion) {
            ubyte[20] buf;
        conn.read(buf);
            throw new SocksException("Incorrect protocol version: " ~ ver[0].to!string ~
            (cast(char[])buf).to!string
            );
        }
    }

    @safe
    void receiveBuffer(TCPConnection conn, ref ubyte[1] len, ref ubyte[] buf)
    {
        conn.read(len);

        logTrace("[%d] Received buffer length: %d", connID, len[0]);

        buf = new ubyte[len[0]];
        conn.read(buf);
    }
}



mixin template Socks5OutgoingPacket()
{
    mixin Socks5Packet;
}

enum bool isSocks5IncomingPacket(P) =
    hasMember!(P, "receive");

enum bool isSocks5OutgoingPacket(P) =
    hasMember!(P, "send");

@safe
struct MethodIdentificationPacket
{
    mixin Socks5IncomingPacket;

    ubyte[1] nmethods;
    ubyte[]  methods;

    void receive(TCPConnection conn)
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

    /*
    unittest
    {
        auto packet = new MethodIdentificationPacket;
        auto sp = socketPair();
        immutable ubyte[] input = [
            0x05,
            0x01,
            AuthMethod.NOAUTH
        ];

        sp[0].send(input);
        packet.receive(sp[1]);

        assert(packet.getVersion() == 5);
        assert(packet.getNMethods() == 1);
        assert(packet.detectAuthMethod([AuthMethod.NOAUTH]) == AuthMethod.NOAUTH);
        assert(packet.detectAuthMethod([AuthMethod.AUTH]) == AuthMethod.NOTAVAILABLE);
    } */
}

@safe
struct MethodSelectionPacket
{
    mixin Socks5OutgoingPacket;

    ubyte[1] method;

    void send(TCPConnection conn)
    {
        conn.write(ver);
        conn.write(method);
    }

    AuthMethod getMethod()
    {
        return cast(AuthMethod)method[0];
    }

    void setMethod(AuthMethod method)
    {
        this.method[0] = method;
    }
}

@safe
struct AuthPacket
{
    mixin Socks5IncomingPacket;

    ubyte[1]  ulen;
    ubyte[]   uname;
    ubyte[1]  plen;
    ubyte[]   passwd;

    void receive(TCPConnection conn)
    {
        receiveVersion(conn, 0x01);
        receiveBuffer(conn, ulen, uname);
        receiveBuffer(conn, plen, passwd);
    }

    @property @trusted
    string login()
    {
        return cast(string)uname;
    }

    @property @trusted
    string password()
    {
        return cast(string)passwd;
    }

/*
    unittest
    {
        auto packet = new AuthPacket;
        auto sp = socketPair();
        immutable ubyte[] input = [
            0x01,
            5,
            't', 'u', 's', 'e', 'r',
            7,
            't', 'p', 'a', 's', 's', 'w', 'd'
        ];

        sp[0].send(input);
        packet.receive(sp[1]);

        assert(packet.getVersion() == 1);
        assert(packet.login == "tuser");
        assert(packet.password == "tpasswd");
    } */
}

@safe
struct AuthStatusPacket
{
    mixin Socks5OutgoingPacket;

    private ubyte[1] status = [0x00];

    void send(TCPConnection conn)
    {
        conn.write(ver);
        conn.write(status);
    }

    AuthStatus getStatus()
    {
        return cast(AuthStatus)status[0];
    }

    void setStatus(AuthStatus status)
    {
        this.status[0] = status;
    }
}

@safe
struct RequestPacket
{
    mixin Socks5IncomingPacket;

    RequestCmd[1]  cmd;
    ubyte[1]       rsv;
    AddressType[1] atyp;
    ubyte[]        dstaddr;
    ubyte[2]       dstport;

    private string host;

    // fill structure with data from socket
    void receive(TCPConnection conn)
    {
        receiveVersion(conn);
        readRequestCommand(conn);
        conn.read(rsv);

        logTrace("[%d] Received rsv: %d", connID, rsv[0]);

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

    private void readRequestCommand(TCPConnection conn)
    {
        conn.read(cast(ubyte[1])cmd);

        logTrace("[%d] Received request command: %s", connID, cmd[0]);

        if (cmd[0] != RequestCmd.CONNECT) {
            throw new RequestException(ReplyCode.CMD_NOTSUPPORTED,
                "Only CONNECT method is supported, given " ~ cmd[0].to!string);
        }
    }

    @trusted
    private void readAddressAndPort(TCPConnection conn)
    {
        conn.read(cast(ubyte[1])atyp);

        switch (atyp[0]) {
            case AddressType.IPV4:
                logTrace("[%d] Address type: IPV4", connID);

                dstaddr = new ubyte[4];
                conn.read(dstaddr);
                conn.read(dstport);

                host = InternetAddress.addrToString(dstaddr.read!uint);
                break;

            case AddressType.DOMAIN:
                logTrace("[%d] Adress type: DOMAIN", connID);

                ubyte[1] length;
                receiveBuffer(conn, length, dstaddr);
                conn.read(dstport);
                host = stringDstaddr();

                logDebug("[%d] Request connect to %s", connID, host);
                break;

            case AddressType.IPV6:
                logTrace("[%d] Address type: IPV6", connID);

                throw new RequestException(ReplyCode.ADDR_NOTSUPPORTED, "AddressType=ipv6 is not supported");

            default:
                logTrace("[%d] Address type: UNKNOWN", connID);

                throw new RequestException(ReplyCode.ADDR_NOTSUPPORTED, "Unknown AddressType: " ~ atyp[0]);
        }
    }

    @trusted
    private string stringDstaddr()
    {
        return cast(string)dstaddr;
    }

/*
@todo
    /// test IPv4 address type
    unittest
    {
        auto packet = new RequestPacket;
        auto sp = socketPair();
        immutable ubyte[] input = [
            0x05,
            0x01,
            0x00,
            AddressType.IPV4,
            10, 0, 35, 94,
            0x00, 0x50 // port 80
        ];

        sp[0].send(input);
        packet.receive(sp[1]);

        assert(packet.getVersion() == 5);
        assert(packet.getDestinationAddress().toString() == "10.0.35.94:80");
    }

    /// test domain address type
    unittest
    {
        auto packet = new RequestPacket;
        auto sp = socketPair();
        immutable ubyte[] input = [
            0x05,
            0x01,
            0x00,
            AddressType.DOMAIN,
            9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
            0x00, 0x50 // port 80
        ];

        sp[0].send(input);
        packet.receive(sp[1]);

        assert(packet.getVersion() == 5);
        assert(packet.getDestinationAddress().toString() == "127.0.0.1:80");
    } */
}


@safe
struct ResponsePacket
{
    mixin Socks5OutgoingPacket;

    private struct ResponsePacketFields
    {
        align(1):

        ReplyCode   rep = ReplyCode.SUCCEEDED;
        ubyte       rsv = 0x00;
        AddressType atyp;
        uint        bndaddr;
        ushort      bndport;
    }

    private union
    {
        ResponsePacketFields fields;
        ubyte[fields.sizeof] buffer;
    }

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

    void send(TCPConnection conn)
    {
        conn.write(ver);
        conn.write(buffer);
    }

    bool setBindAddress(NetworkAddress address)
    {
        fields.bndport = address.port;
        fields.bndaddr = address.sockAddrInet4.sin_addr.s_addr;

        logTrace("[%d] Local target address: %s", connID, address.toString());

        return true;
    }
/*
    unittest
    {
        auto packet = new ResponsePacket;
        auto sp = socketPair();
        immutable ubyte[] output = [
            0x05,
            ReplyCode.SUCCEEDED,
            0x00,
            AddressType.IPV4,
            127, 0, 0, 1, // 127.0.0.1
            0x00, 0x51    // port 81
        ];

        packet.setBindAddress(new InternetAddress("127.0.0.1", 81));

        packet.send(sp[0]);
        ubyte[output.length] buf;
        sp[1].receive(buf);

        assert(buf == output);
    } */
}
