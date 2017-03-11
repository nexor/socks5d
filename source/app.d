import core.stdc.stdio;
immutable char[] nullTerminatedStr = "Hello, World!\0";

int main()
{
    puts(nullTerminatedStr.ptr);

    return 0;
}