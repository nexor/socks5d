import std.stdio;
import socks5d.server;

int main()
{
    writeln("Starting socks5d server v. 0.0.1");

    auto server = new Server(1080);
    server.start();

    return 0;
}
