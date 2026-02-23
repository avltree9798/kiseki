#!/bin/bash
#
# Kiseki OS - Disk Image Creation & Population Script
#
# Creates an Ext4 filesystem image and installs the full Mach-O userland:
#   - dyld (/usr/lib/dyld)
#   - libSystem.B.dylib (/usr/lib/libSystem.B.dylib)
#   - bash shell (/bin/bash)
#   - coreutils (/bin/*, /usr/bin/*, /sbin/*)
#   - init/getty/login (/sbin/init, /sbin/getty, /bin/login)
#   - Configuration files (/etc/*)
#
# All binaries are arm64 Mach-O, loaded by dyld on Kiseki OS.
#
# Usage: ./scripts/mkdisk.sh [output_path] [size_mb]
#
# On Linux: uses loop mount (requires sudo)
# On macOS: uses debugfs from e2fsprogs (brew install e2fsprogs)
#

set -euo pipefail

DISK_IMG="${1:-build/disk.img}"
DISK_SIZE_MB="${2:-64}"
BUILDDIR="build/userland"
SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
PROJDIR="$(cd "${SCRIPTDIR}/.." && pwd)"

echo "=== Kiseki Disk Image Builder ==="
echo "  Image:  ${DISK_IMG}"
echo "  Size:   ${DISK_SIZE_MB}MB"
echo ""

# Ensure build directory exists
mkdir -p "$(dirname "${DISK_IMG}")"

# Create empty disk image
dd if=/dev/zero of="${DISK_IMG}" bs=1M count="${DISK_SIZE_MB}" 2>/dev/null
echo "  [1/4] Created ${DISK_SIZE_MB}MB disk image"

# Find mkfs.ext4
MKFS=""
for cmd in mkfs.ext4 /opt/homebrew/opt/e2fsprogs/sbin/mkfs.ext4 /usr/local/opt/e2fsprogs/sbin/mkfs.ext4; do
    if command -v "$cmd" >/dev/null 2>&1; then
        MKFS="$cmd"
        break
    fi
done

if [ -z "${MKFS}" ]; then
    echo "ERROR: mkfs.ext4 not found."
    echo "  On macOS:  brew install e2fsprogs"
    echo "  On Linux:  apt install e2fsprogs"
    exit 1
fi

# Create Ext4 filesystem with 4KB blocks
# Note: Must use -b 4096 to ensure files can be larger than 12KB
# (ext4 direct blocks: 12 blocks * block_size = max file size without indirection)
"${MKFS}" -q \
    -b 4096 \
    -L "kiseki-root" \
    -O extents,dir_index \
    "${DISK_IMG}"
echo "  [2/4] Formatted as Ext4 (label: kiseki-root, 4KB blocks)"

# ============================================================================
# Binary layout
# ============================================================================

# Binaries that go in /bin (essential commands)
BIN_PROGS="bash cat cp mv rm ln ls mkdir rmdir chmod echo head tail
           grep sed awk cut tr wc sort uniq tee touch sleep kill time timeout
           date hostname uname test true false printf expr basename dirname
           login su passwd ps clear sync vi
           ifconfig ping nc curl ntpdate test_tcc test_puts writetest"

# Test binaries (only included if INCLUDE_TESTS=1)
TEST_PROGS="test_libc"
if [ "${INCLUDE_TESTS:-0}" = "1" ]; then
    BIN_PROGS="${BIN_PROGS} ${TEST_PROGS}"
    echo "  Including test binaries: ${TEST_PROGS}"
fi

# Binaries that go in /usr/bin (non-essential utilities)
USR_BIN_PROGS="find xargs id whoami which env du wc yes tcc file"

# Binaries that go in /sbin (system admin)
SBIN_PROGS="mount umount chown adduser useradd usermod df sudo init getty halt reboot shutdown sshd mDNSResponder"

# Test binary
MACHO_HELLO="${PROJDIR}/build/hello"

# ============================================================================
# Populate the filesystem
# ============================================================================

populate_linux() {
    local MOUNT_DIR
    MOUNT_DIR="$(mktemp -d)"

    sudo mount -o loop "${DISK_IMG}" "${MOUNT_DIR}"

    # Create directory hierarchy
    sudo mkdir -p "${MOUNT_DIR}"/{bin,sbin,usr/{bin,lib,sbin},etc,dev,proc,sys,tmp}
    sudo mkdir -p "${MOUNT_DIR}"/{var/{log,run},root,home,Users}
    sudo mkdir -p "${MOUNT_DIR}"/etc/skel

    # Set permissions
    sudo chmod 1777 "${MOUNT_DIR}/tmp"
    sudo chmod 700  "${MOUNT_DIR}/root"

    # Install /bin binaries
    for prog in ${BIN_PROGS}; do
        if [ -f "${BUILDDIR}/bin/${prog}" ]; then
            sudo cp "${BUILDDIR}/bin/${prog}" "${MOUNT_DIR}/bin/${prog}"
            sudo chmod 755 "${MOUNT_DIR}/bin/${prog}"
        fi
    done
    # sh -> bash symlink
    sudo ln -sf bash "${MOUNT_DIR}/bin/sh"

    # Install /usr/bin binaries
    for prog in ${USR_BIN_PROGS}; do
        if [ -f "${BUILDDIR}/bin/${prog}" ]; then
            sudo cp "${BUILDDIR}/bin/${prog}" "${MOUNT_DIR}/usr/bin/${prog}"
            sudo chmod 755 "${MOUNT_DIR}/usr/bin/${prog}"
        fi
    done

    # Install /sbin binaries (from build/userland/sbin/ and build/userland/bin/)
    for prog in ${SBIN_PROGS}; do
        if [ -f "${BUILDDIR}/sbin/${prog}" ]; then
            sudo cp "${BUILDDIR}/sbin/${prog}" "${MOUNT_DIR}/sbin/${prog}"
            sudo chmod 755 "${MOUNT_DIR}/sbin/${prog}"
        elif [ -f "${BUILDDIR}/bin/${prog}" ]; then
            sudo cp "${BUILDDIR}/bin/${prog}" "${MOUNT_DIR}/sbin/${prog}"
            sudo chmod 755 "${MOUNT_DIR}/sbin/${prog}"
        fi
    done

    # Set SUID bit on su and sudo
    [ -f "${MOUNT_DIR}/bin/su" ] && sudo chmod 4755 "${MOUNT_DIR}/bin/su"
    [ -f "${MOUNT_DIR}/sbin/sudo" ] && sudo chmod 4755 "${MOUNT_DIR}/sbin/sudo"

    # Install dynamic linker (dyld)
    if [ -f "${BUILDDIR}/dyld/dyld" ]; then
        sudo cp "${BUILDDIR}/dyld/dyld" "${MOUNT_DIR}/usr/lib/dyld"
        sudo chmod 755 "${MOUNT_DIR}/usr/lib/dyld"
        echo "  Installed /usr/lib/dyld"
    fi

    # Install libSystem.B.dylib
    if [ -f "${BUILDDIR}/lib/libSystem.B.dylib" ]; then
        sudo cp "${BUILDDIR}/lib/libSystem.B.dylib" "${MOUNT_DIR}/usr/lib/libSystem.B.dylib"
        sudo chmod 755 "${MOUNT_DIR}/usr/lib/libSystem.B.dylib"
        echo "  Installed /usr/lib/libSystem.B.dylib"
    fi

    # Install hello test binary
    if [ -f "${MACHO_HELLO}" ]; then
        sudo cp "${MACHO_HELLO}" "${MOUNT_DIR}/bin/hello"
        sudo chmod 755 "${MOUNT_DIR}/bin/hello"
    fi

    # Install configuration files
    install_config_files "${MOUNT_DIR}"

    # Create LaunchDaemons directories and install plists
    sudo mkdir -p "${MOUNT_DIR}/System/Library/LaunchDaemons"
    sudo mkdir -p "${MOUNT_DIR}/Library/LaunchDaemons"
    local CONFIGDIR="${PROJDIR}/config/LaunchDaemons"
    if [ -d "${CONFIGDIR}" ]; then
        for plist in ${CONFIGDIR}/*.plist; do
            if [ -f "$plist" ]; then
                sudo cp "$plist" "${MOUNT_DIR}/System/Library/LaunchDaemons/$(basename $plist)"
            fi
        done
    fi

    sudo umount "${MOUNT_DIR}"
    rmdir "${MOUNT_DIR}" 2>/dev/null || true
}

populate_debugfs() {
    # Find debugfs
    local DEBUGFS=""
    for cmd in debugfs /opt/homebrew/opt/e2fsprogs/sbin/debugfs /usr/local/opt/e2fsprogs/sbin/debugfs; do
        if command -v "$cmd" >/dev/null 2>&1; then
            DEBUGFS="$cmd"
            break
        fi
    done

    if [ -z "${DEBUGFS}" ]; then
        echo "  WARNING: debugfs not found. Image created but empty."
        echo "  Install e2fsprogs: brew install e2fsprogs"
        return 1
    fi

    # Build a debugfs command script
    local CMDS
    CMDS="$(mktemp)"

    # Create directory hierarchy
    cat >> "${CMDS}" << 'DIRS'
mkdir bin
mkdir sbin
mkdir usr
mkdir usr/bin
mkdir usr/lib
mkdir usr/sbin
mkdir etc
mkdir etc/skel
mkdir dev
mkdir proc
mkdir sys
mkdir tmp
mkdir var
mkdir var/log
mkdir var/run
mkdir root
mkdir home
mkdir Users
DIRS

    # Install /bin binaries
    for prog in ${BIN_PROGS}; do
        if [ -f "${BUILDDIR}/bin/${prog}" ]; then
            echo "write ${BUILDDIR}/bin/${prog} /bin/${prog}" >> "${CMDS}"
        fi
    done
    # sh -> bash symlink
    echo "symlink /bin/sh bash" >> "${CMDS}"

    # Install /usr/bin binaries
    for prog in ${USR_BIN_PROGS}; do
        if [ -f "${BUILDDIR}/bin/${prog}" ]; then
            echo "write ${BUILDDIR}/bin/${prog} /usr/bin/${prog}" >> "${CMDS}"
        fi
    done

    # Install /sbin binaries (from sbin/ dir or bin/ dir)
    for prog in ${SBIN_PROGS}; do
        if [ -f "${BUILDDIR}/sbin/${prog}" ]; then
            echo "write ${BUILDDIR}/sbin/${prog} /sbin/${prog}" >> "${CMDS}"
        elif [ -f "${BUILDDIR}/bin/${prog}" ]; then
            echo "write ${BUILDDIR}/bin/${prog} /sbin/${prog}" >> "${CMDS}"
        fi
    done

    # Install dynamic linker (dyld)
    if [ -f "${BUILDDIR}/dyld/dyld" ]; then
        echo "write ${BUILDDIR}/dyld/dyld /usr/lib/dyld" >> "${CMDS}"
    fi

    # Install libSystem.B.dylib
    if [ -f "${BUILDDIR}/lib/libSystem.B.dylib" ]; then
        echo "write ${BUILDDIR}/lib/libSystem.B.dylib /usr/lib/libSystem.B.dylib" >> "${CMDS}"
    fi

    # Install TCC from tcc build directory
    if [ -f "${BUILDDIR}/tcc/tcc" ]; then
        echo "write ${BUILDDIR}/tcc/tcc /usr/bin/tcc" >> "${CMDS}"
    fi

    # Install C headers for TCC
    echo "mkdir /usr/include" >> "${CMDS}"
    echo "mkdir /usr/include/sys" >> "${CMDS}"
    echo "mkdir /usr/include/arpa" >> "${CMDS}"
    echo "mkdir /usr/include/netinet" >> "${CMDS}"
    local INCDIR="${PROJDIR}/userland/libsystem/include"
    for hdr in ${INCDIR}/*.h; do
        if [ -f "$hdr" ]; then
            echo "write $hdr /usr/include/$(basename $hdr)" >> "${CMDS}"
        fi
    done
    for hdr in ${INCDIR}/sys/*.h; do
        if [ -f "$hdr" ]; then
            echo "write $hdr /usr/include/sys/$(basename $hdr)" >> "${CMDS}"
        fi
    done
    for hdr in ${INCDIR}/arpa/*.h; do
        if [ -f "$hdr" ]; then
            echo "write $hdr /usr/include/arpa/$(basename $hdr)" >> "${CMDS}"
        fi
    done
    for hdr in ${INCDIR}/netinet/*.h; do
        if [ -f "$hdr" ]; then
            echo "write $hdr /usr/include/netinet/$(basename $hdr)" >> "${CMDS}"
        fi
    done

    # Install Mach headers for TCC
    echo "mkdir /usr/include/mach" >> "${CMDS}"
    for hdr in ${INCDIR}/mach/*.h; do
        if [ -f "$hdr" ]; then
            echo "write $hdr /usr/include/mach/$(basename $hdr)" >> "${CMDS}"
        fi
    done

    # Install servers/ headers for TCC (bootstrap.h)
    echo "mkdir /usr/include/servers" >> "${CMDS}"
    if [ -f "${INCDIR}/servers/bootstrap.h" ]; then
        echo "write ${INCDIR}/servers/bootstrap.h /usr/include/servers/bootstrap.h" >> "${CMDS}"
    fi

    # Create /System/Library/LaunchDaemons directory hierarchy
    echo "mkdir /System" >> "${CMDS}"
    echo "mkdir /System/Library" >> "${CMDS}"
    echo "mkdir /System/Library/LaunchDaemons" >> "${CMDS}"

    # Create /Library/LaunchDaemons for third-party daemons
    echo "mkdir /Library" >> "${CMDS}"
    echo "mkdir /Library/LaunchDaemons" >> "${CMDS}"

    # Install plist config files for system daemons
    local CONFIGDIR="${PROJDIR}/config/LaunchDaemons"
    if [ -d "${CONFIGDIR}" ]; then
        for plist in ${CONFIGDIR}/*.plist; do
            if [ -f "$plist" ]; then
                echo "write $plist /System/Library/LaunchDaemons/$(basename $plist)" >> "${CMDS}"
            fi
        done
    fi

    # Install hello test binary
    if [ -f "${MACHO_HELLO}" ]; then
        echo "write ${MACHO_HELLO} /bin/hello" >> "${CMDS}"
    fi

    # Create /etc/issue (pre-login banner)
    local ISSUE_TMP="${TMPDIR:-/tmp}/_issue_$$"
    cat > "${ISSUE_TMP}" << 'ISSUE'

   _  ___          _    _    ___  ___
  | |/ (_)___ ___ | | _(_)  / _ \/ __|
  | ' <| (_-</ -_)| |/ / | | (_) \__ \
  |_|\_\_/__/\___||_|\_\_|  \___/|___/

  Kiseki OS v0.1 - ARM64 Hybrid Kernel

ISSUE
    echo "write ${ISSUE_TMP} /etc/issue" >> "${CMDS}"

    # Create config files using temporary files
    local TMPDIR
    TMPDIR="$(mktemp -d)"
    create_config_tmpfiles "${TMPDIR}"

    for f in passwd shadow group hostname fstab profile sudoers epoch resolv.conf; do
        if [ -f "${TMPDIR}/${f}" ]; then
            echo "write ${TMPDIR}/${f} /etc/${f}" >> "${CMDS}"
        fi
    done

    # Write the .bashrc and .profile for root
    if [ -f "${TMPDIR}/bashrc" ]; then
        echo "write ${TMPDIR}/bashrc /root/.bashrc" >> "${CMDS}"
    fi
    if [ -f "${TMPDIR}/dot_profile" ]; then
        echo "write ${TMPDIR}/dot_profile /root/.profile" >> "${CMDS}"
    fi
    # Write skel files for new users (different from root files)
    if [ -f "${TMPDIR}/skel_bashrc" ]; then
        echo "write ${TMPDIR}/skel_bashrc /etc/skel/.bashrc" >> "${CMDS}"
    fi
    if [ -f "${TMPDIR}/skel_profile" ]; then
        echo "write ${TMPDIR}/skel_profile /etc/skel/.profile" >> "${CMDS}"
    fi

    # Set SUID bit on su and sudo (mode 04755 = 0104755 octal)
    # sif <file> mode <value> sets the inode mode field
    echo "sif /bin/su mode 0104755" >> "${CMDS}"
    echo "sif /sbin/sudo mode 0104755" >> "${CMDS}"

    # Run debugfs
    "${DEBUGFS}" -w -f "${CMDS}" "${DISK_IMG}" >/dev/null 2>&1

    # Clean up
    rm -rf "${TMPDIR}" "${CMDS}" "${ISSUE_TMP}"
}

install_config_files() {
    local MOUNT_DIR="$1"

    sudo tee "${MOUNT_DIR}/etc/passwd" > /dev/null << 'PASSWD'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/bin/false
nobody:x:65534:65534:nobody:/nonexistent:/usr/bin/false
PASSWD

    sudo tee "${MOUNT_DIR}/etc/shadow" > /dev/null << 'SHADOW'
root:toor:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
nobody:*:19000:0:99999:7:::
SHADOW
    sudo chmod 600 "${MOUNT_DIR}/etc/shadow"

    sudo tee "${MOUNT_DIR}/etc/group" > /dev/null << 'GROUP'
root:x:0:
wheel:x:10:root
sudo:x:27:
daemon:x:1:
users:x:100:
nogroup:x:65534:
# Reserved space for group membership expansion
#.............................................................................
#.............................................................................
#.............................................................................
#.............................................................................
#.............................................................................
#.............................................................................
#.............................................................................
#.............................................................................
#.............................................................................
#.............................................................................
#.............................................................................
#.............................................................................
GROUP

    sudo tee "${MOUNT_DIR}/etc/hostname" > /dev/null << 'HOSTNAME'
kiseki
HOSTNAME

    sudo tee "${MOUNT_DIR}/etc/fstab" > /dev/null << 'FSTAB'
# <device>    <mount>   <type>  <options>       <dump> <pass>
/dev/vda      /         ext4    defaults        0      1
FSTAB

    sudo tee "${MOUNT_DIR}/etc/profile" > /dev/null << 'PROFILE'
# Kiseki OS - System-wide profile
# Only set defaults for variables that aren't already set

# PATH - always set
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

# TERM - default if not set
[ -z "$TERM" ] && export TERM=vt100

# PS1 - default prompt (uses \u for username from environment)
export PS1='\u@\h:\w\$ '
PROFILE

    sudo tee "${MOUNT_DIR}/etc/sudoers" > /dev/null << 'SUDOERS'
# Kiseki OS sudoers
root ALL=(ALL) NOPASSWD: ALL
%sudo ALL=(ALL) ALL
SUDOERS
    sudo chmod 440 "${MOUNT_DIR}/etc/sudoers"

    # Boot epoch (seconds since Unix epoch, for date command)
    sudo bash -c "date +%s > '${MOUNT_DIR}/etc/epoch'"

    # DNS resolver configuration
    # On macOS, DNS is configured via scutil/configd. On Unix, /etc/resolv.conf.
    # Default to Google Public DNS (8.8.8.8) and Cloudflare (1.1.1.1).
    sudo tee "${MOUNT_DIR}/etc/resolv.conf" > /dev/null << 'RESOLV'
# Kiseki OS - DNS Resolver Configuration
# Edit this file to change DNS servers.
# Format: nameserver <IPv4 address>
nameserver 8.8.8.8
nameserver 1.1.1.1
RESOLV

    # Root user dotfiles
    sudo tee "${MOUNT_DIR}/root/.bashrc" > /dev/null << 'BASHRC'
# Kiseki OS - Root .bashrc
export PS1='\u@\h:\w# '
alias ls='ls -F'
alias ll='ls -la'
alias la='ls -A'
alias ..='cd ..'
BASHRC

    sudo tee "${MOUNT_DIR}/root/.profile" > /dev/null << 'DOTPROFILE'
# Kiseki OS - Root .profile
if [ -f ~/.bashrc ]; then
    . ~/.bashrc
fi
DOTPROFILE

    # Create /etc/skel files for new users (different from root)
    sudo tee "${MOUNT_DIR}/etc/skel/.bashrc" > /dev/null << 'SKELBASHRC'
# Kiseki OS - User .bashrc
# This file is sourced for interactive non-login shells

# Prompt with username, hostname, and current directory
export PS1='\u@\h:\w\$ '

# Useful aliases
alias ls='ls -F'
alias ll='ls -la'
alias la='ls -A'
alias ..='cd ..'
alias ...='cd ../..'

# History settings
export HISTSIZE=1000
export HISTFILESIZE=2000

# Don't put duplicate lines in history
export HISTCONTROL=ignoredups:ignorespace
SKELBASHRC

    sudo tee "${MOUNT_DIR}/etc/skel/.profile" > /dev/null << 'SKELPROFILE'
# Kiseki OS - User .profile
# This file is sourced for login shells

# Set PATH
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:$HOME/bin

# Source .bashrc if it exists (for interactive login shells)
if [ -f "$HOME/.bashrc" ]; then
    . "$HOME/.bashrc"
fi
SKELPROFILE
}

create_config_tmpfiles() {
    local DIR="$1"

    cat > "${DIR}/passwd" << 'PASSWD'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/bin/false
nobody:x:65534:65534:nobody:/nonexistent:/usr/bin/false
PASSWD

    cat > "${DIR}/shadow" << 'SHADOW'
root:toor:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
nobody:*:19000:0:99999:7:::
SHADOW

    cat > "${DIR}/group" << 'GROUP'
root:x:0:
wheel:x:10:root
sudo:x:27:
daemon:x:1:
users:x:100:
nogroup:x:65534:
GROUP

    cat > "${DIR}/hostname" << 'HOSTNAME'
kiseki
HOSTNAME

    cat > "${DIR}/fstab" << 'FSTAB'
# <device>    <mount>   <type>  <options>       <dump> <pass>
/dev/vda      /         ext4    defaults        0      1
FSTAB

    cat > "${DIR}/profile" << 'PROFILE'
# Kiseki OS - System-wide profile
# Only set defaults for variables that aren't already set

# PATH - always set
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

# TERM - default if not set
[ -z "$TERM" ] && export TERM=vt100

# PS1 - default prompt (uses \u for username from environment)
export PS1='\u@\h:\w\$ '
PROFILE

    cat > "${DIR}/sudoers" << 'SUDOERS'
# Kiseki OS sudoers
root ALL=(ALL) NOPASSWD: ALL
%sudo ALL=(ALL) ALL
SUDOERS

    date +%s > "${DIR}/epoch"

    # DNS resolver configuration
    cat > "${DIR}/resolv.conf" << 'RESOLV'
# Kiseki OS - DNS Resolver Configuration
# Edit this file to change DNS servers.
# Format: nameserver <IPv4 address>
nameserver 8.8.8.8
nameserver 1.1.1.1
RESOLV

    cat > "${DIR}/bashrc" << 'BASHRC'
# Kiseki OS - Root .bashrc
export PS1='\u@\h:\w# '
alias ls='ls -F'
alias ll='ls -la'
alias la='ls -A'
alias ..='cd ..'
BASHRC

    cat > "${DIR}/dot_profile" << 'DOTPROFILE'
# Kiseki OS - Root .profile
if [ -f ~/.bashrc ]; then
    . ~/.bashrc
fi
DOTPROFILE

    # Skel files for new users
    cat > "${DIR}/skel_bashrc" << 'SKELBASHRC'
# Kiseki OS - User .bashrc
export PS1='\u@\h:\w\$ '
alias ls='ls -F'
alias ll='ls -la'
alias la='ls -A'
alias ..='cd ..'
alias ...='cd ../..'
export HISTSIZE=1000
export HISTFILESIZE=2000
export HISTCONTROL=ignoredups:ignorespace
SKELBASHRC

    cat > "${DIR}/skel_profile" << 'SKELPROFILE'
# Kiseki OS - User .profile
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:$HOME/bin
if [ -f "$HOME/.bashrc" ]; then
    . "$HOME/.bashrc"
fi
SKELPROFILE
}

# ============================================================================
# Main logic
# ============================================================================

# Ensure build directories exist
mkdir -p "${BUILDDIR}/bin" "${BUILDDIR}/sbin"

# Count binaries
BIN_COUNT=$(ls "${BUILDDIR}/bin/" "${BUILDDIR}/sbin/" 2>/dev/null | wc -l | tr -d ' ')
if [ "${BIN_COUNT}" -eq 0 ]; then
    echo "  WARNING: No binaries found in ${BUILDDIR}/{bin,sbin}/"
    echo "  Run 'make -C userland' first to build userland programs."
fi

echo "  [3/4] Installing ${BIN_COUNT} Mach-O userland binaries..."

if [[ "$(uname)" == "Linux" ]]; then
    populate_linux
elif [[ "$(uname)" == "Darwin" ]]; then
    populate_debugfs
else
    echo "  WARNING: Unsupported platform. Image created but empty."
fi

echo "  [4/4] Disk image ready"
echo ""
echo "=== Done: ${DISK_IMG} (${DISK_SIZE_MB}MB Ext4) ==="
echo ""
echo "Contents (all arm64 Mach-O):"
echo "  /usr/lib/dyld              - Dynamic linker"
echo "  /usr/lib/libSystem.B.dylib - C library"
echo "  /sbin/init                 - PID 1 init process"
echo "  /sbin/getty                - Terminal login prompt"
echo "  /bin/login                 - User authentication"
echo "  /bin/bash                  - Shell"
echo "  /bin/*                     - Core utilities"
echo "  /etc/*                     - Configuration files"
echo ""
echo "To boot:  make run"
