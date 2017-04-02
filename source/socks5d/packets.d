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

auto get(T)(Socket s)
{
    union buffer {
        ubyte[T.sizeof] b;
        T v;
    }
    buffer buf;

    s.receive(buf.b);

    return buf.v;
}

// read from socket into variable length buffer
void getv(alias TLEN, alias TBUF)(Socket s)
{
    TLEN = s.get!ubyte;
    TBUF = new ubyte[TLEN];

    s.receive(TBUF);
}

mixin template SocksVersion()
{
    ubyte ver; //should be 0x05 (or 0x01 for auth)

    void receiveVersion(Socket socket, ubyte requiredVersion = 0x05)
    {
        ver = socket.get!ubyte;
        if (ver != requiredVersion) {
            throw new SocksException("Incorrect protocol version: " ~ ver.to!string);
        }
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
    mixin   SocksVersion;
    ubyte   nmethods;
    ubyte[] methods;

    void receive(Socket socket)
    {
        receiveVersion(socket);
        getv!(nmethods, methods)(socket);
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
}

struct MethodSelectionPacket
{
    ubyte ver = 0x05;
    ubyte method;
}

struct AuthPacket
{
    mixin   SocksVersion;
    ubyte   ulen;
    ubyte[] uname;
    ubyte   plen;
    ubyte[] passwd;

    void receive(Socket socket)
    {
        receiveVersion(socket, 0x01);
        getv!(ulen, uname)(socket);
        getv!(plen, passwd)(socket);
    }

    string getUsername()
    {
        return to!string( cast(char[])uname );
    }

    string getPassword()
    {
        return to!string( cast(char[])passwd );
    }
}

struct AuthStatusPacket
{
    ubyte ver = 0x05;
    ubyte status = 0x00;
}

struct RequestPacket
{
    mixin SocksVersion;
    RequestCmd  cmd;
    ubyte       rsv = 0x00;
    AddressType atyp;
    ubyte[]     dstaddr;
    ubyte[2]    dstport;

    private InternetAddress address;

    // fill structure with data from socket
    InternetAddress receive(Socket socket)
    {
        receiveVersion(socket);
        readRequestCommand(socket);
        rsv = socket.get!ubyte;
        address = readAddressAndPort(socket);

        return address;
    }

    void readRequestCommand(Socket socket)
    {
        cmd = socket.get!RequestCmd;
        if (cmd != RequestCmd.CONNECT) {
            throw new RequestException(ReplyCode.CMD_NOTSUPPORTED,
                "Only CONNECT method is supported, given " ~ cmd.to!string);
        }
    }

    InternetAddress readAddressAndPort(Socket socket)
    {
        atyp = socket.get!AddressType;

        switch (atyp) {
            case AddressType.IPV4:
                dstaddr = new ubyte[4];
                socket.receive(dstaddr);
                socket.receive(dstport);

                return new InternetAddress(dstaddr.read!uint, dstport.bigEndianToNative!ushort);

            case AddressType.DOMAIN:
                ubyte length;
                getv!(length, dstaddr)(socket);
                socket.receive(dstport);

                return new InternetAddress(cast(char[])dstaddr, dstport.bigEndianToNative!ushort);

            case AddressType.IPV6:
                throw new RequestException(ReplyCode.ADDR_NOTSUPPORTED, "AddressType=ipv6 is not supported");

            default:
                throw new RequestException(ReplyCode.ADDR_NOTSUPPORTED, "Unknown AddressType: " ~ atyp);
        }
    }

    string dstAddressString()
    {
        if (atyp == AddressType.IPV4) {
            return address.toAddrString();
        }
        if (atyp == AddressType.DOMAIN) {
            return to!string(cast(char[])dstaddr);
        }

        return "(unknown)";
    }
}

align(2) struct ResponsePacket
{
    ubyte       ver = 0x05;
    ReplyCode   rep;
    ubyte       rsv = 0x00;
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
