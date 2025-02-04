# minestat.py - A Minecraft server status checker
# Copyright (C) 2016-2023 Lloyd Dilley, Felix Ern (MindSolve)
# http://www.dilley.me/
#
# Secondary optimization and customization are carried out by @molanp.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
import asyncio
import base64
import contextlib
from enum import Enum
import io
import dns.asyncresolver
import dns.name
import idna
import json
import random
import re
import socket
import struct
from time import perf_counter, time


class ConnStatus(Enum):
    """
    Contains possible connection states.

    - `SUCCESS`: The specified SLP connection succeeded (Request & response parsing OK)
    - `CONNFAIL`: The socket to the server could not be established. Server offline, wrong hostname or port?
    - `TIMEOUT`: The connection timed out. (Server under too much load? Firewall rules OK?)
    - `UNKNOWN`: The connection was established, but the server spoke an unknown/unsupported SLP protocol.
    """

    def __str__(self) -> str:
        return str(self.name)

    SUCCESS = 0
    """The specified SLP connection succeeded (Request & response parsing OK)"""

    CONNFAIL = -1
    """The socket to the server could not be established. (Server offline, wrong hostname or port?)"""

    TIMEOUT = -2
    """The connection timed out. (Server under too much load? Firewall rules OK?)"""

    UNKNOWN = -3
    """The connection was established, but the server spoke an unknown/unsupported SLP protocol."""


class SlpProtocols(Enum):
    """
    Contains possible SLP (Server List Ping) protocols.

    - `ALL`: Try all protocols.

      Attempts to connect to a remote server using all available protocols until an acceptable response
      is received or until failure.

    - `QUERY`: The Query / GameSpot4 / UT3 protocol for Mincraft Java servers.
      Needs to be enabled on the Minecraft server.
      Query is similar to SLP but additionally returns more technical related data.

      *Available since Minecraft 1.9*

    - `BEDROCK_RAKNET`: The Minecraft Bedrock/Education edition protocol.

      *Available for all Minecraft Bedrock versions, not compatible with Java edition.*

    - `JSON`: The newest and currently supported SLP protocol.

      Uses (wrapped) JSON as payload. Complex query, see `json_query()` for the protocol implementation.

      *Available since Minecraft 1.7*
    - `EXTENDED_LEGACY`: The previous SLP protocol

      Used by Minecraft 1.6, it is still supported by all newer server versions.
      Complex query needed, see implementation `extended_legacy_query()` for full protocol details.

      *Available since Minecraft 1.6*
    - `LEGACY`: The legacy SLP protocol.

      Used by Minecraft 1.4 and 1.5, it is the first protocol to contain the server version number.
      Very simple protocol call (2 byte), simple response decoding.
      See `legacy_query()` for full implementation and protocol details.

      *Available since Minecraft 1.4*
    - `BETA`: The first SLP protocol.

      Used by Minecraft Beta 1.8 till Release 1.3, it is the first SLP protocol.
      It contains very few details, no server version info, only MOTD, max- and online player counts.

      *Available since Minecraft Beta 1.8*
    """

    def __str__(self) -> str:
        return str(self.name)

    ALL = 5
    """
  Attempt to use all protocols.
  """

    QUERY = 6
    """
  The Query / GameSpot4 / UT3 protocol for Mincraft Java servers.
  Needs to be enabled on the Minecraft server.

  Query is similar to SLP but additionally returns more technical related data.

  *Available since Minecraft 1.9*
  """

    BEDROCK_RAKNET = 4
    """
  The Bedrock SLP-equivalent using the RakNet `Unconnected Ping` packet.

  Currently experimental.
  """

    JSON = 3
    """
  The newest and currently supported SLP protocol.

  Uses (wrapped) JSON as payload. Complex query, see `json_query()` for the protocol implementation.

  *Available since Minecraft 1.7*
  """

    EXTENDED_LEGACY = 2
    """The previous SLP protocol

  Used by Minecraft 1.6, it is still supported by all newer server versions.
  Complex query needed, see implementation `extended_legacy_query()` for full protocol details.

  *Available since Minecraft 1.6*
  """

    LEGACY = 1
    """
  The legacy SLP protocol.

  Used by Minecraft 1.4 and 1.5, it is the first protocol to contain the server version number.
  Very simple protocol call (2 byte), simple response decoding.
  See `legacy_query()` for full implementation and protocol details.

  *Available since Minecraft 1.4*
  """

    BETA = 0
    """
  The first SLP protocol.

  Used by Minecraft Beta 1.8 till Release 1.3, it is the first SLP protocol.
  It contains very few details, no server version info, only MOTD, max- and online player counts.

  *Available since Minecraft Beta 1.8*
  """


class MineStat:
    VERSION = "2.6.3"
    """The MineStat version"""
    DEFAULT_TCP_PORT = 25565
    """default TCP port for SLP queries"""
    DEFAULT_BEDROCK_PORT_V4 = 19132
    """default UDP port for Bedrock/MCPE IPv4 servers"""
    DEFAULT_BEDROCK_PORT_V6 = 19133
    """default UDP port for Bedrock/MCPE IPv6 servers"""
    DEFAULT_TIMEOUT = 5
    """default TCP timeout in seconds"""

    def __init__(
        self,
        address: str,
        port: int = 0,
        timeout: int = DEFAULT_TIMEOUT,
        query_protocol: SlpProtocols = SlpProtocols.ALL,
        refer: str | None = None,
        use_ipv6: bool = False,
    ) -> None:
        """
        minestat - The Minecraft status checker. Supports Minecraft Java edition and Bedrock/Education/PE servers.

        :param address: Hostname or IP address of the Minecraft server.
        :param port: Optional port of the Minecraft server. Defaults to auto detection (25565 for Java Edition, 19132 for Bedrock/MCPE).
        :param timeout: Optional timeout in seconds for each connection attempt. Defaults to 5 seconds.
        :param query_protocol: Optional protocol to use. See minestat.SlpProtocols for available choices. Defaults to auto detection.
        :param refer: The source of IP in the send packet Default use address.
        :param use_ipv6: Optional, whether to use ip_v6 for DNS resolution. Defaults to False.
        """

        """Whether to use ip_v6 for DNS resolution"""
        self.use_ipv6: bool | None = use_ipv6

        """The source of the IP in the sent packet"""
        self.refer = address if refer is None else refer
        self.address: str = address
        """hostname or IP address of the Minecraft server"""

        autoport: bool = False
        if not port:
            autoport = True
            if query_protocol is SlpProtocols.BEDROCK_RAKNET:
                if use_ipv6:
                    port = self.DEFAULT_BEDROCK_PORT_V6
                else:
                    port = self.DEFAULT_BEDROCK_PORT_V4
            else:
                port = self.DEFAULT_TCP_PORT

        self.port: int = port
        """port number the Minecraft server accepts connections on"""
        self.online: bool = False
        """online or offline?"""
        self.version: str | None = None
        """server version"""
        self.plugins: list[str] | None = None
        """list of plugins returned by the Query protcol, may be empty"""
        self.motd: str | None = None
        """message of the day, unchanged server response (including formatting codes/JSON)"""
        self.stripped_motd: str | None = None
        """message of the day, stripped of all formatting ("human-readable")"""
        self.current_players: int | None = None
        """current number of players online"""
        self.max_players: int | None = None
        """maximum player capacity"""
        self.player_list: list[str] | None = None
        """list of online players, may be empty even if "current_players" is over 0"""
        self.map: str | None = None
        """the name of the map the server is running on, only supported by the Query protocol"""
        self.latency: int | None = None
        """ping time to server in milliseconds"""
        self.timeout: int = timeout
        """socket timeout"""
        self.slp_protocol: SlpProtocols | None = None
        """Server List Ping protocol"""
        self.protocol_version: int | None = None
        """Server protocol version"""
        self.favicon_b64: str | None = None
        """base64-encoded favicon possibly contained in JSON 1.7 responses"""
        self.favicon: str | None = None
        """decoded favicon data"""
        self.gamemode: str | None = None
        """Bedrock specific: The current game mode (Creative/Survival/Adventure)"""
        self.srv_record: bool | None = None
        """wether the server has a SRV record"""
        self.connection_status: ConnStatus | None = None
        """Status of connection ("SUCCESS", "CONNFAIL", "TIMEOUT", or "UNKNOWN")"""

        # Future improvement: IPv4/IPv6, multiple addresses
        # If a host has multiple IP addresses or a IPv4 and a IPv6 address,
        # socket.connect choses the first IPv4 address returned by DNS.
        # If a mc server is not available over IPv4, this failes as "offline".
        # Or in some environments, the DNS returns the external and the internal
        # address, but from an internal client, only the internal address is reachable
        # See https://docs.python.org/3/library/socket.html#socket.getaddrinfo

        # If the user wants a specific protocol, use only that.
        result = ConnStatus.UNKNOWN
        if query_protocol is not SlpProtocols.ALL:
            if query_protocol is SlpProtocols.BETA:
                result = self.beta_query()
            elif query_protocol is SlpProtocols.LEGACY:
                result = self.legacy_query()
            elif query_protocol is SlpProtocols.EXTENDED_LEGACY:
                result = self.extended_legacy_query()
            elif query_protocol is SlpProtocols.JSON:
                result = self.json_query()
            elif query_protocol is SlpProtocols.BEDROCK_RAKNET:
                result = self.bedrock_raknet_query()
            elif query_protocol is SlpProtocols.QUERY:
                result = self.fullstat_query()
            self.connection_status = result

            return

        # Note: The order for Java edition here is unfortunately important.
        # Some older versions of MC don't accept packets for a few seconds
        # after receiving a not understood packet.
        # An example is MC 1.4: Nothing works directly after a json request.
        # A legacy query alone works fine.

        # Minecraft Bedrock/Pocket/Education Edition (MCPE/MCEE)
        if autoport and not self.port:
            if use_ipv6:
                self.port = self.DEFAULT_BEDROCK_PORT_V6
            else:
                self.port = self.DEFAULT_BEDROCK_PORT_V4

        result = self.bedrock_raknet_query()
        self.connection_status = result

        if result is ConnStatus.SUCCESS:
            return

        if autoport and not self.port:
            self.port = self.DEFAULT_TCP_PORT

        # Minecraft 1.4 & 1.5 (legacy SLP)
        result = self.legacy_query()

        # Minecraft Beta 1.8 to Release 1.3 (beta SLP)
        if result not in [ConnStatus.CONNFAIL, ConnStatus.SUCCESS]:
            result = self.beta_query()

        # Minecraft 1.6 (extended legacy SLP)
        if result is not ConnStatus.CONNFAIL:
            result = self.extended_legacy_query()

        # Minecraft 1.7+ (JSON SLP)
        if result is not ConnStatus.CONNFAIL:
            self.json_query()

        self.connection_status = ConnStatus.SUCCESS if self.online else result

    @staticmethod
    def motd_strip_formatting(raw_motd: str | dict) -> str:
        """
        Function for stripping all formatting codes from a motd. Supports Json Chat components (as dict) and
        the legacy formatting codes.

        :param raw_motd: The raw MOTD, either as a string or dict (from "json.loads()")
        """
        stripped_motd = ""

        if isinstance(raw_motd, str):
            stripped_motd = re.sub(r"§.", "", raw_motd)

        elif isinstance(raw_motd, dict):
            stripped_motd = raw_motd.get("text", "")

            if raw_motd.get("extra"):
                for sub in raw_motd["extra"]:
                    stripped_motd += MineStat.motd_strip_formatting(sub)

        return stripped_motd

    def bedrock_raknet_query(self) -> ConnStatus:
        """
        Method for querying a Bedrock server (Minecraft PE, Windows 10 or Education Edition).
        The protocol is based on the RakNet protocol.

        See https://wiki.vg/Raknet_Protocol#Unconnected_Ping

        Note: This method currently works as if the connection is handled via TCP (as if no packet loss might occur).
        Packet loss handling should be implemented (resending).
        """

        RAKNET_MAGIC = bytearray(
            [
                0x00,
                0xFF,
                0xFF,
                0x00,
                0xFE,
                0xFE,
                0xFE,
                0xFE,
                0xFD,
                0xFD,
                0xFD,
                0xFD,
                0x12,
                0x34,
                0x56,
                0x78,
            ]
        )

        # Create socket with type DGRAM (for UDP)
        if self.use_ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(self.timeout)

        try:
            self._extracted_from_beta_query_19(sock)
        except TimeoutError:
            return ConnStatus.TIMEOUT
        except OSError:
            return ConnStatus.CONNFAIL

        # Construct the `Unconnected_Ping` packet
        # Packet ID - 0x01
        req_data = bytearray([0x01])
        # current unix timestamp in ms as signed long (64-bit) LE-encoded
        req_data += struct.pack("<q", int(time() * 1000))
        # RakNet MAGIC (0x00ffff00fefefefefdfdfdfd12345678)
        req_data += RAKNET_MAGIC
        # Client GUID - as signed long (64-bit) LE-encoded
        req_data += struct.pack("<q", 0x02)

        sock.send(req_data)

        # Do all the receiving in a try-catch, to reduce duplication of error handling

        # response packet:
        # byte - 0x1C - Unconnected Pong
        # long - timestamp
        # long - server GUID
        # 16 byte - magic
        # short - Server ID string length
        # string - Server ID string
        try:
            response_buffer, response_addr = sock.recvfrom(1024)
            response_stream = io.BytesIO(response_buffer)

            # Receive packet id
            packet_id = response_stream.read(1)

            # Response packet ID should always be 0x1c
            if packet_id != b"\x1c":
                return ConnStatus.UNKNOWN

            # Receive (& ignore) response timestamp
            response_timestamp = struct.unpack("<q", response_stream.read(8))

            # Server GUID
            response_server_guid = struct.unpack("<q", response_stream.read(8))

            # Magic
            response_magic = response_stream.read(16)
            if response_magic != RAKNET_MAGIC:
                return ConnStatus.UNKNOWN

            # Server ID string length
            response_id_string_length = struct.unpack(">h", response_stream.read(2))

            # Receive server ID string
            response_id_string = response_stream.read().decode("utf8")

        except TimeoutError:
            return ConnStatus.TIMEOUT
        except (ConnectionResetError, ConnectionAbortedError):
            return ConnStatus.UNKNOWN
        except OSError:
            return ConnStatus.CONNFAIL
        finally:
            sock.close()

        # Set protocol version
        self.slp_protocol = SlpProtocols.BEDROCK_RAKNET

        # Parse and save to object attributes
        return self.__parse_bedrock_payload(response_id_string)

    def __parse_bedrock_payload(self, payload_str: str) -> ConnStatus:
        motd_index = [
            "edition",
            "motd_1",
            "protocol_version",
            "version",
            "current_players",
            "max_players",
            "server_uid",
            "motd_2",
            "gamemode",
            "gamemode_numeric",
            "port_ipv4",
            "port_ipv6",
        ]
        payload = dict(zip(motd_index, payload_str.split(";")))

        self.online = True
        self.protocol_version = int(payload["protocol_version"])

        self.current_players = int(payload["current_players"])
        self.max_players = int(payload["max_players"])
        try:
            self.version = (
                payload["version"]
                + " "
                + payload["motd_2"]
                + " ("
                + payload["edition"]
                + ")"
            )
        except (
            KeyError
        ):  # older Bedrock server versions do not respond with the secondary MotD.
            self.version = payload["version"] + " (" + payload["edition"] + ")"

        self.motd = payload["motd_1"]
        self.stripped_motd = self.motd_strip_formatting(self.motd)

        try:
            self.gamemode = payload["gamemode"]
        except (
            KeyError
        ):  # older Bedrock server versions do not respond with the game mode.
            self.gamemode = None

        return ConnStatus.SUCCESS

    def fullstat_query(self) -> ConnStatus:
        """
        Method for querying a Minecraft Java server using the fullstat Query / GameSpot4 / UT3 protocol.
        Needs to be enabled on the Minecraft server using:

        "enable-query=true"

        in the servers "server.properties" file.

        This method ONLY supports full stat querys.
        Documentation for this protocol: https://wiki.vg/Query
        """
        # protocol:
        #   send handshake request
        #   receive challenge token
        #   send full stat request
        #   receive status data

        # Create UDP socket and set timeout
        if self.use_ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        # padding that is prefixes to every packet
        magic = b"\xfe\xfd"

        # packettypes for the multiple packets send by the client
        handshake_packettype = struct.pack("!B", 9)
        stat_packettype = struct.pack("!B", 0)

        # generate session id
        session_id_int = random.randint(0, 2147483648) & 0x0F0F0F0F
        session_id_bytes = struct.pack(">l", session_id_int)

        # handshake packet:
        #   contains 0xFE0xFD as a prefix
        #   contains type of the packet, 9 for hanshaking in this case (encoded in Bytes as a big-endian)
        #   contains session id (is generated randomly at the begining)

        # construct the handshake packet
        handshake_packet = magic
        handshake_packet += handshake_packettype
        handshake_packet += session_id_bytes

        # send packet to server
        sock.sendto(handshake_packet, (self.address, self.port))

        try:
            # receive the handshake response
            handshake_res = sock.recv(24)

            # extract the challenge token from the server. The beginning of the packet can be ignored.
            challenge_token = handshake_res[5:].rstrip(b"\00")

            # pack the challenge token into a big-endian long (int32)
            challenge_token_bytes = struct.pack(">l", int(challenge_token))

            # full stat request packet:
            #   contains 0xFE0xFD as a prefix
            #   contains type of the packet, 0 for hanshaking in this case (encoded as a big-endian integer)
            #   contains session id (is generated randomly at the beginning)
            #   contains challenge token (received during the handshake)
            #   contains 0x00 0x00 0x00 0x00 as padding (a basic stat request does not include these bytes)

            # construct the request packet
            req_packet = magic
            req_packet += stat_packettype
            req_packet += session_id_bytes
            req_packet += challenge_token_bytes
            req_packet += b"\x00\x00\x00\x00"

            # send packet to server
            sock.sendto(req_packet, (self.address, self.port))

            # receive requested status data
            raw_res = sock.recv(4096)

            # close the socket
            sock.close()

        except TimeoutError:
            return ConnStatus.TIMEOUT
        except (ConnectionResetError, ConnectionAbortedError):
            return ConnStatus.UNKNOWN
        except OSError:
            return ConnStatus.CONNFAIL
        finally:
            sock.close()

        return self.__parse_query_payload(raw_res)

    def __parse_query_payload(self, raw_res) -> ConnStatus:
        """
        Helper method for parsing the reponse from a query request.

        See https://wiki.vg/Query for details.

        This implementation does not parse every value returned by the query protocol.
        """
        try:
            self.__extracted_from___parse_query_payload_11(raw_res)
        except Exception:
            return ConnStatus.UNKNOWN

        self.online = True
        self.slp_protocol = SlpProtocols.QUERY
        return ConnStatus.SUCCESS

    def __extracted_from___parse_query_payload_11(self, raw_res):
        # remove uneccessary padding
        res = raw_res[11:]

        # split stats from players
        raw_stats, raw_players = res.split(b"\x00\x00\x01player_\x00\x00")

        # split stat keys and values into individual elements and remove unnecessary padding
        stat_list = raw_stats.split(b"\x00")[2:]

        # move keys and values into a dictonary, the keys are also decoded
        key = True
        stats = {}
        for index, key_name in enumerate(stat_list):
            if key:
                stats[key_name.decode("utf-8")] = stat_list[index + 1]
                key = False
            else:
                key = True

        # extract motd, the motd is named "hostname" in the Query protocol
        if "hostname" in stats:
            self.motd = stats["hostname"].decode("iso_8859_1")

        # the "MOTD" key is used in a basic stats query reponse
        elif "MOTD" in stats:
            self.motd = stats["MOTD"].decode("iso_8859_1")

        if self.motd is not None:
            # remove potential formatting
            self.stripped_motd = self.motd_strip_formatting(self.motd)

        # extract the servers Minecraft version
        if "version" in stats:
            self.version = stats["version"].decode("utf-8")

            # extract list of plugins
        if "plugins" in stats:
            raw_plugins = stats["plugins"].decode("utf-8")
            if raw_plugins != "":
                # the plugins are separated by " ;"
                self.plugins = raw_plugins.split(" ;")
                # there may be information about the server software in the first plugin element
                # example: ["Paper on 1.19.3: AnExampleMod 7.3", "AnotherExampleMod 4.2", ...]
                # more information on https://wiki.vg/Query
                if ":" in self.plugins[0]:  # type: ignore
                    self.version, self.plugins[0] = self.plugins[0].split(": ")  # type: ignore

        # extract the name of the map the server is running on
        if "map" in stats:
            self.map = stats["map"].decode("utf-8")

        if "numplayers" in stats:
            self.current_players = int(stats["numplayers"])
            self.max_players = int(stats["maxplayers"])

        # split players (seperated by 0x00)
        players = raw_players.split(b"\x00")

        # decode players and sort out empty elements
        self.player_list = [
            player.decode("utf-8") for player in players[:-2] if player != b""
        ]

    def json_query(self) -> ConnStatus:
        """
        Method for querying a modern (MC Java >= 1.7) server with the SLP protocol.
        This protocol is based on encoded JSON, see the documentation at wiki.vg below
        for a full packet description.

        See https://wiki.vg/Server_List_Ping#Current
        """
        if self.use_ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            self._extracted_from_beta_query_19(sock)
        except TimeoutError:
            return ConnStatus.TIMEOUT
        except OSError:
            return ConnStatus.CONNFAIL

        # Construct Handshake packet
        req_data = bytearray([0x00])
        # Add protocol version. If pinging to determine version, use `-1`
        req_data += bytearray([0xFF, 0xFF, 0xFF, 0xFF, 0x0F])
        # Add server address length
        req_data += self._pack_varint(len(self.refer))
        # Server address. Encoded with UTF8
        req_data += bytearray(self.refer, "utf8")
        # Server port
        req_data += struct.pack(">H", self.port)
        # Next packet state (1 for status, 2 for login)
        req_data += bytearray([0x01])

        # Prepend full packet length
        req_data = self._pack_varint(len(req_data)) + req_data

        # Now actually send the constructed client request
        sock.send(req_data)

        # Now send empty "Request" packet
        # varint len, 0x00
        sock.send(bytearray([0x01, 0x00]))

        # Do all the receiving in a try-catch, to reduce duplication of error handling
        try:
            # Receive answer: full packet length as varint
            packet_len = self._unpack_varint(sock)

            # Check if full packet length seems acceptable
            if packet_len < 3:
                return ConnStatus.UNKNOWN

            # Receive actual packet id
            packet_id = self._unpack_varint(sock)

            # If we receive a packet with id 0x19, something went wrong.
            # Usually the payload is JSON text, telling us what exactly.
            # We could stop here, and display something to the user, as this is not normal
            # behaviour, maybe a bug somewhere here.

            # Instead I am just going to check for the correct packet id: 0x00
            if packet_id != 0:
                return ConnStatus.UNKNOWN

            # Receive & unpack payload length
            content_len = self._unpack_varint(sock)

            # Receive full payload
            payload_raw = self._recv_exact(sock, content_len)

        except TimeoutError:
            return ConnStatus.TIMEOUT
        except (ConnectionResetError, ConnectionAbortedError):
            return ConnStatus.UNKNOWN
        except OSError:
            return ConnStatus.CONNFAIL
        finally:
            sock.close()

        # Set protocol version
        self.slp_protocol = SlpProtocols.JSON

        # Parse and save to object attributes
        return self.__parse_json_payload(payload_raw)

    def __parse_json_payload(self, payload_raw: bytes | bytearray) -> ConnStatus:
        """
        Helper method for parsing the modern JSON-based SLP protocol.
        In use for Minecraft Java >= 1.7, see `json_query()` above for details regarding the protocol.

        :param payload_raw: The raw SLP payload, without header and string lenght
        """
        try:
            payload_obj = json.loads(payload_raw.decode("utf8"))
        except json.JSONDecodeError:
            return ConnStatus.UNKNOWN

        # Now that we have the status object, set all fields
        self.version = payload_obj["version"]["name"]
        self.protocol_version = payload_obj["version"]["protocol"]

        # The motd might be a string directly, not a json object
        if isinstance(payload_obj.get("description", ""), str):
            self.motd = payload_obj.get("description", "")
        else:
            self.motd = json.dumps(payload_obj["description"])
        self.stripped_motd = self.motd_strip_formatting(
            payload_obj.get("description", "")
        )

        players = payload_obj.get("players", {})
        self.max_players = players.get("max", -1)
        self.current_players = players.get("online", -1)

        # There may be a "sample" field in the "players" object that contains a sample list of online players
        if "sample" in players:
            self.player_list = [player["name"] for player in players["sample"]]

        try:
            self.favicon_b64 = payload_obj["favicon"]
            if self.favicon_b64:
                self.favicon = str(
                    base64.b64decode(self.favicon_b64.split("base64,")[1]), "ISO-8859–1"
                )
        except KeyError:
            self.favicon_b64 = None
            self.favicon = None

        # If we got here, everything is in order.
        self.online = True
        return ConnStatus.SUCCESS

    def _unpack_varint(self, sock: socket.socket) -> int:
        """Small helper method for unpacking an int from an varint (streamed from socket)."""
        data = 0
        for i in range(5):
            ordinal = sock.recv(1)

            if len(ordinal) == 0:
                break

            byte = ord(ordinal)
            data |= (byte & 0x7F) << 7 * i

            if not byte & 0x80:
                break

        return data

    def _pack_varint(self, data) -> bytes:
        """Small helper method for packing a varint from an int."""
        ordinal = b""

        while True:
            byte = data & 0x7F
            data >>= 7
            ordinal += struct.pack("B", byte | (0x80 if data > 0 else 0))

            if data == 0:
                break

        return ordinal

    def extended_legacy_query(self) -> ConnStatus:
        """
        Minecraft 1.6 SLP query, extended legacy ping protocol.
        All modern servers are currently backwards compatible with this protocol.

        See https://wiki.vg/Server_List_Ping#1.6
        :return:
        """
        if self.use_ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            self._extracted_from_beta_query_19(sock)
        except TimeoutError:
            return ConnStatus.TIMEOUT
        except OSError:
            return ConnStatus.CONNFAIL

        # Send 0xFE as packet identifier,
        # 0x01 as ping packet content
        # 0xFA as packet identifier for a plugin message
        # 0x00 0x0B as strlen of following string
        req_data = bytearray([0xFE, 0x01, 0xFA, 0x00, 0x0B])
        # the string 'MC|PingHost' as UTF-16BE encoded string
        req_data += bytearray("MC|PingHost", "utf-16-be")
        # 0xXX 0xXX byte count of rest of data, 7+len(serverhostname), as short
        req_data += struct.pack(">h", 7 + (len(self.refer) * 2))
        # 0xXX [legacy] protocol version (before netty rewrite)
        # Used here: 74 (MC 1.6.2)
        req_data += bytearray([0x49])
        # strlen of serverhostname (big-endian short)
        req_data += struct.pack(">h", len(self.refer))
        # the hostname of the server
        req_data += bytearray(self.refer, "utf-16-be")
        # port of the server, as int (4 byte)
        req_data += struct.pack(">i", self.port)

        # Now send the contructed client requests
        sock.send(req_data)

        try:
            # Receive answer packet id (1 byte)
            packet_id = self._recv_exact(sock, 1)

            # Check packet id (should be "kick packet 0xFF")
            if packet_id[0] != 0xFF:
                return ConnStatus.UNKNOWN

            # Receive payload lengh (signed big-endian short; 2 byte)
            raw_payload_len = self._recv_exact(sock, 2)

            # Extract payload length
            # Might be empty, if the server keeps the connection open but doesn't send anything
            content_len = struct.unpack(">h", raw_payload_len)[0]

            # Check if payload length is acceptable
            if content_len < 3:
                return ConnStatus.UNKNOWN

            # Receive full payload and close socket
            payload_raw = self._recv_exact(sock, content_len * 2)

        except TimeoutError:
            return ConnStatus.TIMEOUT
        except (ConnectionResetError, ConnectionAbortedError, struct.error):
            return ConnStatus.UNKNOWN
        except OSError:
            return ConnStatus.CONNFAIL
        finally:
            sock.close()

        # Set protocol version
        self.slp_protocol = SlpProtocols.EXTENDED_LEGACY

        # Parse and save to object attributes
        return self.__parse_legacy_payload(payload_raw)

    def legacy_query(self) -> ConnStatus:
        """
        Minecraft 1.4-1.5 SLP query, server response contains more info than beta SLP

        See https://wiki.vg/Server_List_Ping#1.4_to_1.5

        :return: ConnStatus
        """
        if self.use_ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            self._extracted_from_beta_query_19(sock)
        except TimeoutError:
            return ConnStatus.TIMEOUT
        except OSError:
            return ConnStatus.CONNFAIL

        # Send 0xFE 0x01 as packet id
        sock.send(bytearray([0xFE, 0x01]))

        # Receive answer packet id (1 byte) and payload lengh (signed big-endian short; 2 byte)
        try:
            raw_header = self._recv_exact(sock, 3)
        except TimeoutError:
            return ConnStatus.TIMEOUT
        except (ConnectionAbortedError, ConnectionResetError):
            return ConnStatus.UNKNOWN
        except OSError:
            return ConnStatus.CONNFAIL

        # Extract payload length
        # Might be empty, if the server keeps the connection open but doesn't send anything
        try:
            content_len = struct.unpack(">xh", raw_header)[0]
        except struct.error:
            return ConnStatus.UNKNOWN

        try:
            # Receive full payload and close socket
            payload_raw = bytearray(self._recv_exact(sock, content_len * 2))
        except TimeoutError:
            return ConnStatus.TIMEOUT
        except (ConnectionResetError, ConnectionAbortedError):
            return ConnStatus.UNKNOWN
        except OSError:
            return ConnStatus.CONNFAIL
        sock.close()

        # Set protocol version
        self.slp_protocol = SlpProtocols.LEGACY

        # Parse and save to object attributes
        return self.__parse_legacy_payload(payload_raw)

    def __parse_legacy_payload(self, payload_raw: bytearray | bytes) -> ConnStatus:
        """
        Internal helper method for parsing the legacy SLP payload (legacy and extended legacy).

        :param payload_raw: The extracted legacy SLP payload as bytearray/bytes
        """
        # According to wiki.vg, beta, legacy and extended legacy use UTF-16BE as "payload" encoding
        payload_str = payload_raw.decode("utf-16-be")

        # This "payload" contains six fields delimited by a NUL character:
        # - a fixed prefix '§1'
        # - the protocol version
        # - the server version
        # - the MOTD
        # - the online player count
        # - the max player count
        payload_list = payload_str.split("\x00")

        # Check for count of string parts, expected is 6 for this protocol version
        if len(payload_list) != 6:
            return ConnStatus.UNKNOWN

        # - a fixed prefix '§1'
        # - the protocol version
        self.protocol_version = int(payload_list[1][1:]) if payload_list[1] else 0
        # - the server version
        self.version = payload_list[2]
        # - the MOTD
        self.motd = payload_list[3]
        self.stripped_motd = self.motd_strip_formatting(payload_list[3])
        # - the online player count
        self.current_players = int(payload_list[4])
        # - the max player count
        self.max_players = int(payload_list[5])

        # If we got here, everything is in order
        self.online = True
        return ConnStatus.SUCCESS

    def beta_query(self) -> ConnStatus:
        """
        Minecraft Beta 1.8 to Release 1.3 SLP protocol
        See https://wiki.vg/Server_List_Ping#Beta_1.8_to_1.3

        :return: ConnStatus
        """
        if self.use_ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            self._extracted_from_beta_query_19(sock)
        except TimeoutError:
            return ConnStatus.TIMEOUT
        except (ConnectionResetError, ConnectionAbortedError):
            return ConnStatus.UNKNOWN
        except OSError:
            return ConnStatus.CONNFAIL

        # Send 0xFE as packet id
        sock.send(bytearray([0xFE]))

        # Receive answer packet id (1 byte) and payload lengh (signed big-endian short; 2 byte)
        try:
            raw_header = self._recv_exact(sock, 3)
        except TimeoutError:
            return ConnStatus.TIMEOUT
        except (ConnectionResetError, ConnectionAbortedError):
            return ConnStatus.UNKNOWN
        except OSError:
            return ConnStatus.CONNFAIL

        # Extract payload length
        # Might be empty, if the server keeps the connection open but doesn't send anything
        try:
            content_len = struct.unpack(">xh", raw_header)[0]
        except struct.error:
            return ConnStatus.UNKNOWN

        # Receive full payload and close socket
        payload_raw = bytearray(self._recv_exact(sock, content_len * 2))
        sock.close()

        # Set protocol version
        self.slp_protocol = SlpProtocols.BETA

        # According to wiki.vg, beta, legacy and extended legacy use UTF-16BE as "payload" encoding
        payload_str = payload_raw.decode("utf-16-be")
        # This "payload" contains three values:
        # The MOTD, the max player count, and the online player count
        payload_list = payload_str.split("§")

        # Check for count of string parts, expected is 3 for this protocol version
        # Note: We could check here if the list has the len() one, as that is most probably an error message.
        # e.g. ['Protocol error']
        if len(payload_list) < 3:
            return ConnStatus.UNKNOWN

        # The last value is the max player count
        self.max_players = int(payload_list[-1])
        # The second(-to-last) value is the online player count
        self.current_players = int(payload_list[-2])
        # The first value it the server MOTD
        # This could contain '§' itself, thats the reason for the join here
        self.motd = "§".join(payload_list[:-2])
        self.stripped_motd = self.motd_strip_formatting("§".join(payload_list[:-2]))

        # Set general version, as the protocol doesn't contain the server version
        self.version = ">=1.8b/1.3"

        # If we got here, everything is in order
        self.online = True

        return ConnStatus.SUCCESS

    def _extracted_from_beta_query_19(self, sock):
        start_time = perf_counter()
        sock.connect((self.address, self.port))
        self.latency = round((perf_counter() - start_time) * 1000)

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytearray:
        """
        Helper function for receiving a specific amount of data. Works around the problems of `socket.recv`.
        Throws a ConnectionAbortedError if the connection was closed while waiting for data.

        :param sock: Open socket to receive data from
        :param size: Amount of bytes of data to receive
        :return: bytearray with the received data
        """
        data = bytearray()

        while len(data) < size:
            if temp_data := bytearray(sock.recv(size - len(data))):
                data += temp_data

            else:
                raise ConnectionAbortedError

        return data


class Checker:
    def __init__(self, ip: str, port: int = 0, timeout: int = 5):
        """Initializes Checker with given IP, port, and timeout.

        Args:
            ip (str): The IP address of the Minecraft server.
            port (int, optional): The port of the server. Defaults to 0.'0' means auto-detect.
            timeout (int, optional): The timeout for queries. Defaults to 5.
        """
        self.address = ip
        self.port = port
        self.timeout = timeout
        self.auto_port = self.port == 0

    async def get_servers(self, ip, port, ip_type, refer) -> list[MineStat | None]:
        """
        获取Java版和Bedrock版的MC服务器信息。

        参数:
        - ip (str): 服务器的IP地址。
        - port (int): 服务器的端口。
        - ip_type (int): 服务器的IP类型。
        - refer (str): 服务器来源地址

        返回:
        - list: 包含Java版和Bedrock版服务器信息的列表。
        """
        loop = asyncio.get_event_loop()
        if ip_type.startswith("SRV"):
            return [
                await loop.run_in_executor(
                    None, self.get_java, ip, port, ip_type, refer
                )
            ]
        return [
            await loop.run_in_executor(None, self.get_java, ip, port, ip_type, refer),
            await loop.run_in_executor(
                None, self.get_bedrock, ip, port, ip_type, refer
            ),
        ]

    async def check(self) -> list[MineStat] | ConnStatus:
        """
        异步函数，根据初始化类时传入的IP和端口获取查询成功的MineStat实例列表。

        返回:
        - list: 包含MineStat实例的列表。
        """
        ip_groups = await self.get_origin_address(self.address, self.port)
        self.ip = ip_groups[0]
        results = await asyncio.gather(
            *(
                self.get_servers(ip_group[0], ip_group[1], ip_group[2], ip_group[3])
                for ip_group in ip_groups
            )
        )
        results = [item for sublist in results for item in sublist]
        result = [ms for ms in results if not isinstance(ms, ConnStatus)]
        if not result:
            result.append(
                next(
                    (ms for ms in results if ms != ConnStatus.CONNFAIL),
                    ConnStatus.CONNFAIL,
                )
            )
        return result

    def get_bedrock(
        self, host: str, port: int, ip_type: str, refer: str
    ) -> MineStat | None:
        """
        异步函数，用于通过指定的主机名、端口和超时时间获取Minecraft Bedrock版服务器状态。

        参数:
        - host: 服务器的主机名。
        - port: 服务器的端口号。
        - ip_type: 服务器地址类型。
        - refer: 服务器地址来源。

        返回:
        - MineStat实例，包含服务器状态信息，如果服务器在线的话；否则可能返回None。
        """
        v6 = "IPv6" in ip_type
        result = MineStat(
            host, port, self.timeout, SlpProtocols.BEDROCK_RAKNET, refer, v6
        )

        return result if result.online else result.connection_status

    def get_java(
        self, host: str, port: int, ip_type: str, refer: str
    ) -> MineStat | None:
        """
        异步函数，用于通过指定的主机名、端口和超时时间获取Minecraft Java版服务器状态。

        参数:
        - host: 服务器的主机名。
        - port: 服务器的端口号。
        - ip_type: 服务器地址类型。
        - refer: 服务器地址来源。

        返回:
        - MineStat 实例，包含服务器状态信息，如果服务器在线的话；否则可能返回 None。
        """
        v6 = "IPv6" in ip_type

        # Minecraft 1.4 & 1.5 (legacy SLP)
        result = MineStat(host, port, self.timeout, SlpProtocols.LEGACY, refer, v6)

        # Minecraft Beta 1.8 to Release 1.3 (beta SLP)
        if result.connection_status not in [ConnStatus.CONNFAIL, ConnStatus.SUCCESS]:
            result = MineStat(host, port, self.timeout, SlpProtocols.BETA, refer, v6)

        # Minecraft 1.6 (extended legacy SLP)
        if result.connection_status is not ConnStatus.CONNFAIL:
            result = MineStat(
                host, port, self.timeout, SlpProtocols.EXTENDED_LEGACY, refer, v6
            )

        # Minecraft 1.7+ (JSON SLP)
        if result.connection_status is not ConnStatus.CONNFAIL:
            result = MineStat(host, port, self.timeout, SlpProtocols.JSON, refer, v6)

        return result if result.online else result.connection_status

    async def is_validity_address(self, address: str) -> bool:
        """
        异步判断给定的地址是否为有效的域名或IP地址。

        参数:
        address (str): 需要验证的地址，可以是域名地址或IP地址。

        返回:
        bool: 如果地址有效则返回True，否则返回False。
        """

        return (
            (await self.is_domain(address))
            or (await self.is_ipv4(address))
            or (await self.is_ipv6(address))
        )

    async def is_domain(self, address: str) -> bool:
        """
        判断给定的地址是否为域名。

        参数:
        address (str): 需要验证的地址。

        返回:
        bool: 如果地址为域名则返回True，否则返回False。
        """
        if address.lower() == "localhost":
            return True
        domain_pattern = re.compile(
            r"^(?!-)(?:[A-Za-z0-9-]{1,63}\.)+(?:[A-Za-z]{2,})$|^(xn--[A-Za-z0-9-]{1,63})\.[A-Za-z]{2,}$"
        )
        try:
            punycode_address = idna.encode(address).decode("utf-8")
            return bool(domain_pattern.match(punycode_address))
        except idna.IDNAError:
            return False

    async def is_ipv4(self, address: str) -> bool:
        """
        判断给定的地址是否为IPv4地址。

        参数:
        address (str): 需要验证的地址。

        返回:
        bool: 如果地址为IPv4地址则返回True，否则返回False。
        """
        ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        match_ipv4 = ipv4_pattern.match(address)

        if not match_ipv4:
            return False

        parts = address.split(".")
        return not any(
            not part.isdigit() or not 0 <= int(part) <= 255 for part in parts
        )

    async def is_ipv6(self, address: str) -> bool:
        """
        判断给定的地址是否为IPv6地址。

        参数:
        address (str): 需要验证的地址。

        返回:
        bool: 如果地址为IPv6地址则返回True，否则返回False。
        """
        ipv6_pattern = re.compile(
            r"^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$"
        )
        match_ipv6 = ipv6_pattern.match(address)

        return bool(match_ipv6)

    async def get_ip_type(self, address: str) -> str:
        if not await self.is_validity_address(address):
            return "Unknown"
        if await self.is_ipv4(address):
            return "IPv4"
        elif await self.is_ipv6(address):
            return "IPv6"
        else:
            return "Domain"

    async def get_origin_address(
        self, domain: str, ip_port: int = 0, is_resolve_srv=True
    ) -> list[tuple[str, int, str, str]]:
        """
        获取地址所解析的A或AAAA记录，如果传入不是域名直接返回。
        同时返回地址是IPv6还是IPv4。
        如果地址是域名，首先尝试解析SRV记录。

        参数:
        - address (str): 需要解析的地址。
        - ip_port (int): 适用于IPv4和IPv6地址的默认端口号。
        - is_resolve_srv (bool): 师是否解析SRV，默认True

        返回:
        - List[Tuple[str, int, str, str]]: 一个列表，包含一个元组，元组包含三个元素：
        - 第一个元素是解析后的地址（字符串形式）。
        - 第二个元素是地址的端口号（整数形式。
        - 第三个元素是地址的类型（"IPv4" 或 "IPv6" 或 "SRV" 或 "SRV-IPv4" 或 "SRV-IPv6"）。
        - 第四个元素是解析地址的来源域名或IP
        """
        ip_type = await self.get_ip_type(domain)
        if ip_type != "Domain":
            return [(domain, ip_port, ip_type, domain)]
        data = []

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 10
        resolver.retries = 3

        async def resolve_srv():
            with contextlib.suppress(
                dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout
            ):
                srv_response = await resolver.resolve(
                    f"_minecraft._tcp.{domain}", "SRV"
                )
                for rdata in srv_response:
                    srv_address = str(rdata.target).rstrip(".")
                    srv_port = rdata.port
                    ip_type = await self.get_ip_type(srv_address)
                    if ip_type == "Domain":
                        srv_address_ = await self.get_origin_address(
                            srv_address, srv_port, False
                        )
                        srv_data = (
                            srv_address_[0][0],
                            srv_address_[0][1],
                            f"SRV-{srv_address_[0][2]}",
                            srv_address_[0][3],
                        )
                        # data.extend([(addr, port, f"SRV-{ip_type}", refer) for addr, port, ip_type, refer in srv_address_])
                    else:
                        srv_data = (
                            srv_address,
                            srv_port,
                            f"SRV-{ip_type}",
                            domain,
                        )
                    if not any(
                        entry[0] == srv_data[0]
                        and entry[1] == srv_data[1]
                        and entry[2].replace("SRV-", "")
                        == srv_data[2].replace("SRV-", "")
                        for entry in data
                    ):
                        data.append(srv_data)
                    break

        async def resolve_aaaa():
            with contextlib.suppress(
                dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout
            ):
                response = await resolver.resolve(domain, "AAAA")
                for rdata in response:
                    data.append((str(rdata.address), ip_port, "IPv6", domain))
                    break

        async def resolve_a():
            with contextlib.suppress(
                dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout
            ):
                response = await resolver.resolve(domain, "A")
                for rdata in response:
                    data.append((str(rdata.address), ip_port, "IPv4", domain))
                    break

        if is_resolve_srv:
            await asyncio.gather(resolve_aaaa(), resolve_a(), resolve_srv())
        else:
            await asyncio.gather(resolve_aaaa(), resolve_a())

        return data
