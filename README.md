# fortiauth
A tiny CLI tool to automate the authentication and keepalive requests for IIT Kanpur's Fortinet captive portal.

Given a username and password this program automatically monitors the network and logs in to the Fortinet captive portal when needed. It also send keepalive requests periodically to maintain the login.

## Installation
Either download a release directly from the releases page or use Go:

    go install github.com/samiksome92/fortiauth@latest

## Usage
    fortiauth [options]

Options:

        --check_time int       Seconds to wait before re-checking state (default 10)
        --dns string           DNS server to use for connections
    -h, --help                 Print this help
        --keepalive_time int   Seconds to wait before sending keepalive request (default 60)
    -f, --pass_file string     File with credentials
    -p, --password string      Password
        --retry_time int       Seconds to wait before retrying operations (default 1)
        --url string           URL to use for checking connection (default "http://google.com")
    -u, --username string      Username
