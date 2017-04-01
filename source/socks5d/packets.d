module socks5d.packets;

import std.stdio;
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

auto get(T)(Socket s, T)
{
    union buffer {
        ubyte[T.sizeof] b;
        T v;
    }
    buffer buf;

    s.receive(buf.b);

    return buf.v;
}

class RequestException : Exception
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
    ubyte   ver = 0x05;
    ubyte   nmethods;
    ubyte[] methods;

    void receive(Socket socket)
    {
        ver = get!(ubyte)(socket, ver);
        nmethods = get!(ubyte)(socket, nmethods);

        methods = new ubyte[nmethods];
        socket.receive(methods);
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

struct RequestPacket
{
    ubyte ver = 0x05;
    RequestCmd cmd;
    ubyte rsv = 0x00;
    AddressType atyp;
    ubyte[] dstaddr;
    ushort dstport;

    // fill structure with data from socket
    InternetAddress receive(Socket socket)
    {
        ver = get!ubyte(socket, ver);
        readRequestCommand(socket);
        rsv = get!(ubyte)(socket, rsv);
        auto address = readAddressAndPort(socket);

        return address;
    }

    void readRequestCommand(Socket socket)
    {
        cmd = get!(RequestCmd)(socket, cmd);
        if (cmd != RequestCmd.CONNECT) {
            throw new RequestException(ReplyCode.CMD_NOTSUPPORTED, "Only CONNECT method is supported");
        }
    }

    InternetAddress readAddressAndPort(Socket socket)
    {
        atyp = get!(AddressType)(socket, atyp);

        switch (atyp) {
            case AddressType.IPV4:
                dstaddr = new ubyte[4];
                socket.receive(dstaddr);

                dstport = swapEndian(get!(ushort)(socket, dstport));

                return new InternetAddress(dstaddr.read!uint(), dstport);

            case AddressType.DOMAIN:
                ubyte length;
                length = get!ubyte(socket, length);
                dstaddr = new ubyte[length];
                socket.receive(dstaddr);

                dstport = swapEndian(get!(ushort)(socket, dstport));

                return new InternetAddress(cast(char[])dstaddr, dstport);

            case AddressType.IPV6:
                throw new RequestException(ReplyCode.ADDR_NOTSUPPORTED, "AddressType=ipv6 is not supported");

            default:
                throw new RequestException(ReplyCode.ADDR_NOTSUPPORTED, "Unknown AddressType: " ~ atyp);
        }
    }
}

align(2) struct ResponsePacket
{
    ubyte ver = 0x05;
    ReplyCode rep;
    ubyte rsv = 0x00;
    AddressType atyp;
    uint bndaddr;
    ushort bndport;

    bool setBindAddress(Address address)
    {
        auto saddr_ptr = address.name;
        auto in_ptr = *(cast(sockaddr_in*) saddr_ptr);

        bndport = to!ushort(address.toPortString());
        bndaddr = in_ptr.sin_addr.s_addr;

        return true;
    }
}
