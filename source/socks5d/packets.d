module socks5d.packets;

import std.socket;
import std.algorithm;
import std.bitmanip;
import std.conv;
import std.c.linux.socket: sockaddr_in, in_addr;

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

void receiveVariableBuffer(alias TLEN, alias TBUF)(Socket s)
{
    s.receive(TLEN);
    TBUF = new ubyte[TLEN[0]];

    s.receive(TBUF);
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
}

struct MethodSelectionPacket
{
    mixin SocksVersion;
    ubyte method;
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
}

struct AuthStatusPacket
{
    mixin SocksVersion;
    ubyte status = 0x00;
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

    void readRequestCommand(Socket socket)
    {
        socket.receive(cmd);
        if (cmd[0] != RequestCmd.CONNECT) {
            throw new RequestException(ReplyCode.CMD_NOTSUPPORTED,
                "Only CONNECT method is supported, given " ~ cmd[0].to!string);
        }
    }

    InternetAddress readAddressAndPort(Socket socket)
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
}

align(2) struct ResponsePacket
{
    mixin SocksVersion;
    ReplyCode   rep = ReplyCode.SUCCEEDED;
    ubyte[1]    rsv = [0x00];
    AddressType atyp;
    uint        bndaddr;
    ushort      bndport;

    bool setBindAddress(Address address)
    {
        auto saddr_ptr = address.name;
        auto in_ptr = *(cast(sockaddr_in*) saddr_ptr);

        bndport = address.toPortString().to!ushort;
        bndaddr = in_ptr.sin_addr.s_addr;

        return true;
    }
}
