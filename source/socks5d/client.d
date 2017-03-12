module socks5d.client;

import core.thread : Thread;
import std.stdio;
import std.datetime : msecs, dur;

enum METHOD_NOAUTH = 0x00;
enum METHOD_AUTH = 0x02;
enum METHOD_NOTAVAILABLE = 0xFF;

struct MethodIdentificationPacket
{
    ubyte ver = 0x05;
    ubyte nmethods;
}

struct MethodSelectionPacket
{
    ubyte ver = 0x05;
    ubyte methods;
}

class Client : Thread
{
    public:
        bool isTerminated;

        this()
        {
            super(&run);
        }

        final void run()
        {
            while (true) {
                writeln("Client is working...");
                Thread.sleep(dur!"msecs"(1000));
                Thread.yield();
            }
        }
}