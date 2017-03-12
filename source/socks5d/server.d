module socks5d.server;

import socks5d.client;
import core.thread : Thread;
import std.stdio, std.socket;
import std.datetime : msecs, dur;

class Server : Thread
{
    private:
        ushort port;
        int backlog;
        Socket socket;
        SocketSet set;

        this ()
        {
            super(&run);
        }
    public:
        this(ushort port = 1080, int backlog = 10)
        {
            this.port = port;
            this.backlog = backlog;

            super(&run);
        }

        final void run()
        {
            int counter = 10;
            auto client = new Client;
            client.start();

            while(counter--) {
                writeln("Server is running... ", counter);
                Thread.sleep(dur!"msecs"(2000));
                Thread.yield();
            }
        }
}
