module socks5d.packets;

import std.socket;
import std.bitmanip;
import std.conv;

enum AuthMethod : ubyte {
    NOAUTH = 0x00,
    AUTH = 0x02,
    NOTAVAILABLE = 0xFF
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
        result ~= format("%s=%s ", T.tupleof[index].stringof, value);
    }

    return result;
}

long receiveVariableBuffer(alias TLEN, alias TBUF)(Socket s)
{
    s.receive(TLEN);
    TBUF = new ubyte[TLEN[0]];

    return s.receive(TBUF);
}

mixin template SocksVersion()
{
    ubyte[1] ver = [0x05]; //should be 0x05 (or 0x01 for auth)

    void receiveVersion(Socket socket, ubyte requiredVersion = 0x05)
    {
        socket.receive(ver);
        if (ver[0] != requiredVersion) {
            throw new SocksException("Incorrect protocol version: " ~ ver[0].to!string);
        }
    }

    ubyte getVersion()
    {
        return ver[0];
    }
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

abstract class Socks5Packet
{
    ubyte[1] ver = [0x05]; //should be 0x05 (or 0x01 for auth)

    ubyte getVersion()
    {
        return ver[0];
    }
}

abstract class IncomingPacket: Socks5Packet
{
    void receiveVersion(Socket socket, ubyte requiredVersion = 0x05)
    {
        socket.receive(ver);
        if (ver[0] != requiredVersion) {
            throw new SocksException("Incorrect protocol version: " ~ ver[0].to!string);
        }
    }
}

abstract class OutgoingPacket: Socks5Packet
{
    abstract void send(Socket s);
}

struct MethodIdentificationPacket
{
    mixin    SocksVersion;
    ubyte[1] nmethods;
    ubyte[]  methods;

    void receive(Socket socket)
    {
        receiveVersion(socket);
        socket.receiveVariableBuffer!(nmethods, methods);
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
        MethodIdentificationPacket packet;
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
    }
}

class MethodSelectionPacket : OutgoingPacket
{
    ubyte method;

    override void send(Socket s)
    {
        s.send(ver);
        s.send((&method)[0..1]);
    }
}

struct AuthPacket
{
    mixin     SocksVersion;
    ubyte[1]  ulen;
    ubyte[]   uname;
    ubyte[1]  plen;
    ubyte[]   passwd;

    void receive(Socket socket)
    {
        receiveVersion(socket, 0x01);
        socket.receiveVariableBuffer!(ulen, uname);
        socket.receiveVariableBuffer!(plen, passwd);
    }

    string getAuthString()
    {
        import std.format : format;

        return format("%s:%s", cast(char[])uname, cast(char[])passwd ) ;
    }

    unittest
    {
        AuthPacket packet;
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
        assert(packet.getAuthString() == "tuser:tpasswd");
    }
}

class AuthStatusPacket : OutgoingPacket
{
    ubyte status = 0x00;

    override void send(Socket s)
    {
        s.send(ver);
        s.send((&status)[0..1]);
    }
}

struct RequestPacket
{
    mixin SocksVersion;
    RequestCmd[1]  cmd;
    ubyte[1]       rsv;
    AddressType[1] atyp;
    ubyte[]        dstaddr;
    ubyte[2]       dstport;

    // fill structure with data from socket
    InternetAddress receive(Socket socket)
    {
        receiveVersion(socket);
        readRequestCommand(socket);
        socket.receive(rsv);
        if (rsv[0] != 0x00) {
            throw new RequestException(ReplyCode.FAILURE, "Received incorrect rsv byte");
        }

        return readAddressAndPort(socket);
    }

    private void readRequestCommand(Socket socket)
    {
        socket.receive(cmd);
        if (cmd[0] != RequestCmd.CONNECT) {
            throw new RequestException(ReplyCode.CMD_NOTSUPPORTED,
                "Only CONNECT method is supported, given " ~ cmd[0].to!string);
        }
    }

    private InternetAddress readAddressAndPort(Socket socket)
    {
        socket.receive(atyp);

        switch (atyp[0]) {
            case AddressType.IPV4:
                dstaddr = new ubyte[4];
                socket.receive(dstaddr);
                socket.receive(dstport);

                return new InternetAddress(dstaddr.read!uint, dstport.bigEndianToNative!ushort);

            case AddressType.DOMAIN:
                ubyte[1] length;
                socket.receiveVariableBuffer!(length, dstaddr);
                socket.receive(dstport);

                return new InternetAddress(cast(char[])dstaddr, dstport.bigEndianToNative!ushort);

            case AddressType.IPV6:
                throw new RequestException(ReplyCode.ADDR_NOTSUPPORTED, "AddressType=ipv6 is not supported");

            default:
                throw new RequestException(ReplyCode.ADDR_NOTSUPPORTED, "Unknown AddressType: " ~ atyp[0]);
        }
    }

    /// test IPv4 address type
    unittest
    {
        RequestPacket packet;
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
        auto address = packet.receive(sp[1]);

        assert(packet.getVersion() == 5);
        assert(address.toString() == "10.0.35.94:80");
    }

    /// test domain address type
    unittest
    {
        RequestPacket packet;
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
        auto address = packet.receive(sp[1]);

        assert(packet.getVersion() == 5);
        assert(address.toString() == "127.0.0.1:80");
    }
}

align(2) struct ResponsePacket
{
    mixin SocksVersion;
    ReplyCode   rep = ReplyCode.SUCCEEDED;
    ubyte[1]    rsv = [0x00];
    AddressType atyp;
    ubyte[4]    bndaddr;
    ubyte[2]    bndport;

    bool setBindAddress(InternetAddress address)
    {
        bndport = nativeToBigEndian(address.port);
        bndaddr = nativeToBigEndian(address.addr);

        return true;
    }

    unittest
    {
        ResponsePacket packet;
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

        sp[0].send((&packet)[0..1]);
        ubyte[output.length] buf;
        sp[1].receive(buf);

        assert(buf == output);
    }
}
