module socks5d.connection;

import std.socket;

@safe
struct Connection
{
    @disable this(this);
    @disable this();

    Socket socket;

    this(Socket s = null)
    {
        if (s !is null) {
            socket = s;
        } else {
            socket = new TcpSocket;
        }
    }

    ptrdiff_t send(const(void)[] buf)
    {
        return socket.send(buf);
    }

    ptrdiff_t receive(void[] buf)
    {
        return socket.receive(buf);
    }

    nothrow @nogc
    void close()
    {
        socket.close();
    }
}