# gpg-bridge
A bridge connects openssh-portable and GnuPG on Windows.

## Usage

1. Install it on your System.

    ```
    cargo install -f --git https://github.com/busyjay/gpg-bridge
    ```

2. Make sure you have setup gpg agent forward following [the guide](https://wiki.gnupg.org/AgentForwarding).

3. Directly using socket provided by GnuPG won't work on Windows, so change local socket to a TCP port instead.

    ```
    RemoteForward <socket_on_remote_box>  127.0.0.1:4321
    ```

    You are free to use any port that has not been taken, `4321` is just an example.

4. Build a bridge between TCP port and GnuPG extra socket.

    ```
    ~/.cargo/bin/gpg-bridge 127.0.0.1:4321
    ```

    If you have customized extra socket localtion, you can append the path as second parameter.

Now you are all set, requests to gpg agent on remote should be able to forward to your local.

## Why invent the wheel

There are several gotchas if not using bridge to forward gpg agent on Windows. See PowerShell/Win32-OpenSSH#1564.

1. Specifying remote forward local socket path in openssh-portable can be tricky (for now).

    Path like `C:/xxx`, `~/xxx` and `%userprofile%/xxx` will not work. You have to use form like
    `/absolute/path/to/local/socket` and execute ssh on the same driver path. See
    https://docs.microsoft.com/en-us/dotnet/standard/io/file-path-formats.

2. Even path is correctly specified and accepted, forwarding will not work.

    Openssh-portable can't handle UDS(unix domain socket) on Windows correctly (for now).

3. Even Openssh-portable handles UDS correctly, forwarding still can't work.

    > Support for Unix domain sockets was introduced in Windows 10 Insider Build 17063. It became generally
    available in version 1809 (aka the October 2018 Update), and in Windows Server 1809/2019.

    GnuPG on Windows has not utilized native UDS support yet. It simulates a UDS using a TCP stream socket with
    customized connect step. So without extra tools, you can't really connect openssh-portable to GnuPG.