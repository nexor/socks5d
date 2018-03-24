module socks5d.factory;

import socks5d.driver;
import std.variant;

version (Socks5dDefaultDriver)
{
    import socks5d.drivers.standard;

    alias ApplicationImpl        = StandardApplication;
    alias ConnectionImpl         = StandardConnection;
    alias ConnectionListenerImpl = StandardConnectionListener;
    alias LoggerImpl             = StandardLogger;
}
else version (Socks5dVibeCoreDriver)
{
    static assert(0, "Under construction");
}
else
{
    static assert(0, "Incorrect build version");
}

/**
*/
@safe @nogc nothrow
@property
Factory f()
{
    return s_factory;
}

/**
*/
@safe @nogc nothrow
@property
LoggerImpl logger()
{
    return s_logger;
}

@safe
final class Factory
{
    Application application()
    {
        return new ApplicationImpl();
    }

    /**
    */
    Connection connection()
    {
        return new ConnectionImpl(logger);
    }

    /**
    */
    ConnectionListener connectionListener()
    {
        return new ConnectionListenerImpl(logger);
    }
}

static this()
{
    s_factory = new Factory;
    s_logger = new LoggerImpl;
}

private {
    Factory    s_factory;
    LoggerImpl s_logger;
}
