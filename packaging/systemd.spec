# "enable foo" will turn into --enable-foo or --disable-foo
# depending "with_foo" macro
%define enable() %{expand:%%{?with_%{1}:--enable-%{1}}%%{!?with_%{1}:--disable-%{1}}}

%define WITH_RANDOMSEED 0
%define WITH_BASH_COMPLETION 0
%define WITH_ZSH_COMPLETION 0
%define WITH_COREDUMP 0
%define WITH_BACKLIGHT 0
%define WITH_TIMEDATED 0
%define WITH_RFKILL 0
%define WITH_MACHINED 0
%define WITH_DOC 0
%define WITH_HOSTNAMED 0

Name:           systemd
Version:        231
Release:        0%{?release_flags}
# For a breakdown of the licensing, see README
License:        LGPL-2.1+ and GPL-2.0+
Summary:        A System and Service Manager
Url:            http://www.freedesktop.org/wiki/Software/systemd
Group:          Base/Startup
Source0:        https://github.com/systemd/systemd/archive/v%{version}.tar.gz
Source1:        pamconsole-tmp.conf
Source2:        %{name}-rpmlintrc
Source3:        test-runner.c
Source1001:     systemd.manifest
BuildRequires:  gperf
BuildRequires:  intltool >= 0.40.0
BuildRequires:  libacl-devel
BuildRequires:  libblkid-devel >= 2.20
BuildRequires:  libcap-devel
BuildRequires:  libgcrypt-devel
BuildRequires:  libkmod-devel >= 14
%if %{?WITH_DOC}
BuildRequires:  xsltproc
BuildRequires:  docbook-xsl-stylesheets
%endif
BuildRequires:  pam-devel
BuildRequires:  pkgconfig
# BuildRequires:  pkgconfig(dbus-1)     # for remove circular dependency on OBS
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(liblzma)
BuildRequires:  pkgconfig(libkmod)
BuildRequires:  pkgconfig(mount)
# Requires:       dbus                  # for remove circular dependency on OBS
Requires:       filesystem
Requires(post): coreutils
Requires(pre):  coreutils
Requires(pre):  /usr/bin/getent
Requires(pre):  /usr/sbin/groupadd

Obsoletes:      SysVinit < 2.86-24
Obsoletes:      sysvinit < 2.86-24
Provides:       SysVinit = 2.86-24
Provides:       sysvinit = 2.86-24
Provides:       /bin/systemctl
Provides:       /sbin/shutdown
Provides:       udev = %{version}
Obsoletes:      udev < 183

%description
systemd is a system and service manager for Linux, compatible with
SysV and LSB init scripts. systemd provides aggressive parallelization
capabilities, uses socket and D-Bus activation for starting services,
offers on-demand starting of daemons, keeps track of processes using
Linux cgroups, supports snapshotting and restoring of the system
state, maintains mount and automount points and implements an
elaborate transactional dependency-based service control logic. It can
work as a drop-in replacement for sysvinit.

%package -n libsystemd
License:        LGPL-2.1+
Summary:        Systemd libraries
Group:          Base/Startup
Obsoletes:      libudev < 183
Provides:       libudev = %{version}
Obsoletes:      systemd < 185-4
Conflicts:      systemd < 185-4

%description -n libsystemd
Libraries for systemd and udev, as well as the systemd PAM module.

%package devel
License:        LGPL-2.1+
Summary:        Development headers for systemd
Requires:       %{name} = %{version}
Requires:		libsystemd = %{version}
Provides:       libudev-devel = %{version}
Obsoletes:      libudev-devel < 183

%description devel
Development headers and auxiliary files for developing applications for systemd.

%package analyze
License:        LGPL-2.1+
Summary:        Tool for processing systemd profiling information
Requires:       %{name} = %{version}
Obsoletes:      systemd < 38-5

%description analyze
'systemd-analyze blame' lists which systemd unit needed how much time to finish
initialization at boot.
'systemd-analyze plot' renders an SVG visualizing the parallel start of units
at boot.

%package tests
License:        LGPL-2.1+ and BSD-2-Clause
Summary:        Set of tests for sd-bus component
Requires:       %{name} = %{version}

%description tests
This package is part of 'dbus-integratnion-tests' framework and contains set of tests
for sd-bus component (DBUS API C library).

%package extension-kdbus
Summary:	Extension for systemd to support KDBUS in Tizen
Requires:	%{name} = %{version}-%{release}

%description extension-kdbus
This modifies systemd to support KDBUS in Tizen.

%prep
%setup -q
cp %{SOURCE1001} .
cp %{SOURCE3} .

%build
%autogen
%configure \
        --enable-kdbus \
%if ! %{WITH_RANDOMSEED}
        --disable-randomseed \
%endif
%if ! %{?WITH_COREDUMP}
	--disable-coredump \
%endif
%if ! %{?WITH_BACKLIGHT}
	--disable-backlight \
%endif
%if ! %{?WITH_TIMEDATED}
	--disable-timedated \
%endif
%if ! %{WITH_RFKILL}
	--disable-rfkill \
%endif
        --enable-compat-libs \
        --disable-hwdb \
        --disable-sysusers \
        --disable-firstboot \
        --disable-polkit \
        --disable-timesyncd \
        --disable-resolved \
        --disable-networkd \
%if ! %{?WITH_MACHINED}
        --disable-machined \
%endif
%if ! %{?WITH_HOSTNAMED}
        --disable-hostnamed \
%endif
        --disable-importd \
        --disable-gcrypt \
        --libexecdir=%{_prefix}/lib \
        --docdir=%{_docdir}/systemd \
%if ! %{?WITH_DOC}
        --disable-manpages \
%endif
        --disable-static \
        --with-rpmmacrosdir=%{_sysconfdir}/rpm/ \
        --with-sysvinit-path= \
        --with-sysvrcnd-path= \
        --with-smack-run-label=System::Privileged \
        cc_cv_CFLAGS__flto=no
make %{?_smp_mflags} \
        systemunitdir=%{_unitdir} \
        userunitdir=%{_unitdir_user}

# compile test-runner for 'dbus-integration-test' framework
%__cc %{_builddir}/%{name}-%{version}/test-runner.c -o %{_builddir}/%{name}-%{version}/systemd-tests

%install
%make_install
%find_lang %{name}
cat <<EOF >> systemd.lang
%lang(be) /usr/lib/systemd/catalog/systemd.be.catalog
%lang(be) /usr/lib/systemd/catalog/systemd.be@latin.catalog
%lang(bg) /usr/lib/systemd/catalog/systemd.bg.catalog
%lang(fr) /usr/lib/systemd/catalog/systemd.fr.catalog
%lang(it) /usr/lib/systemd/catalog/systemd.it.catalog
%lang(pl) /usr/lib/systemd/catalog/systemd.pl.catalog
%lang(pt_BR) /usr/lib/systemd/catalog/systemd.pt_BR.catalog
%lang(ru) /usr/lib/systemd/catalog/systemd.ru.catalog
%lang(zh) /usr/lib/systemd/catalog/systemd.zh_CN.catalog
%lang(zh) /usr/lib/systemd/catalog/systemd.zh_TW.catalog
EOF

# udev links
/usr/bin/mkdir -p %{buildroot}/%{_sbindir}
/usr/bin/ln -sf ../bin/udevadm %{buildroot}%{_sbindir}/udevadm
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/firmware/updates

# Create SysV compatibility symlinks. systemctl/systemd are smart
# enough to detect in which way they are called.
/usr/bin/ln -s ../lib/systemd/systemd %{buildroot}%{_sbindir}/init
/usr/bin/ln -s ../lib/systemd/systemd %{buildroot}%{_bindir}/systemd
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/reboot
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/halt
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/poweroff
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/shutdown
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/telinit
/usr/bin/ln -s ../bin/systemctl %{buildroot}%{_sbindir}/runlevel

# legacy links
/usr/bin/ln -s loginctl %{buildroot}%{_bindir}/systemd-loginctl

# We create all wants links manually at installation time to make sure
# they are not owned and hence overriden by rpm after the used deleted
# them.
/usr/bin/rm -r %{buildroot}%{_sysconfdir}/systemd/system/*.target.wants

# Make sure these directories are properly owned
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/basic.target.wants
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/default.target.wants
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/dbus.target.wants
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/syslog.target.wants

# Make sure the user generators dir exists too
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-generators
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/user-generators

# Create new-style configuration files so that we can ghost-own them
/usr/bin/touch %{buildroot}%{_sysconfdir}/hostname
/usr/bin/touch %{buildroot}%{_sysconfdir}/vconsole.conf
/usr/bin/touch %{buildroot}%{_sysconfdir}/locale.conf
/usr/bin/touch %{buildroot}%{_sysconfdir}/machine-id
/usr/bin/touch %{buildroot}%{_sysconfdir}/machine-info
/usr/bin/touch %{buildroot}%{_sysconfdir}/timezone

/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-preset/
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/user-preset/

# Make sure the shutdown/sleep drop-in dirs exist
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-shutdown/
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-sleep/

# Make sure the NTP units dir exists
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/ntp-units.d/

# Install modprobe fragment
/usr/bin/mkdir -p %{buildroot}%{_sysconfdir}/modprobe.d/

# Fix the dangling /var/lock -> /run/lock symlink
install -Dm644 tmpfiles.d/legacy.conf %{buildroot}%{_prefix}/lib/tmpfiles.d/legacy.conf

install -m644 %{SOURCE1} %{buildroot}%{_prefix}/lib/tmpfiles.d/

install -m 755 -d %{buildroot}/%{_prefix}/lib/systemd/system

rm -rf %{buildroot}/%{_docdir}/%{name}

# Disable some useless services in Tizen
rm -rf %{buildroot}/%{_prefix}/lib/systemd/system/sysinit.target.wants/dev-hugepages.mount
rm -rf %{buildroot}/%{_prefix}/lib/systemd/system/sysinit.target.wants/sys-fs-fuse-connections.mount
rm -rf %{buildroot}/%{_prefix}/lib/systemd/system/sysinit.target.wants/systemd-binfmt.service
rm -rf %{buildroot}/%{_prefix}/lib/systemd/system/sysinit.target.wants/systemd-modules-load.service
rm -rf %{buildroot}/%{_prefix}/lib/systemd/system/sysinit.target.wants/systemd-ask-password-console.path
rm -rf %{buildroot}/%{_prefix}/lib/systemd/system/multi-user.target.wants/systemd-ask-password-wall.path
rm -rf %{buildroot}/%{_prefix}/lib/systemd/system/systemd-tmpfiles-clean.timer
rm -rf %{buildroot}/%{_prefix}/lib/systemd/system/systemd-tmpfiles-clean.service
rm -rf %{buildroot}/%{_prefix}/lib/systemd/system/timers.target.wants/systemd-tmpfiles-clean.timer

# Exclude ELF binaries
rm -f %{buildroot}/%{_prefix}/lib/systemd/system-generators/systemd-debug-generator
rm -f %{buildroot}/%{_prefix}/lib/systemd/system-generators/systemd-efi-boot-generator
rm -f %{buildroot}/%{_prefix}/lib/systemd/system-generators/systemd-gpt-auto-generator
rm -f %{buildroot}/%{_prefix}/lib/systemd/system-generators/systemd-hibernate-resume-generator

# Marker file for kdbus
touch %{buildroot}/%{_sysconfdir}/systemd/extension-kdbus

# Preapre tests for 'dbus-integration-test' framework
install -D -m 755 %{_builddir}/%{name}-%{version}/systemd-tests %{buildroot}%{_prefix}/lib/dbus-tests/runner/systemd-tests
mkdir -p %{buildroot}%{_prefix}/lib/dbus-tests/test-suites/systemd-tests/
mv %{_builddir}/%{name}-%{version}/test-bus-* %{buildroot}%{_prefix}/lib/dbus-tests/test-suites/systemd-tests/

# Shell Completion
%if ! %{?WITH_BASH_COMPLETION}
rm -rf %{buildroot}/%{_datadir}/bash-completion/*
%endif
%if ! %{?WITH_ZSH_COMPLETION}
rm -rf %{buildroot}/%{_datadir}/zsh/site-functions/*
%endif

mkdir -p %{buildroot}/%{_localstatedir}/log/journal

ln -sf ./libsystemd.pc %{buildroot}%{_libdir}/pkgconfig/libsystemd-daemon.pc
ln -sf ./libsystemd.pc %{buildroot}%{_libdir}/pkgconfig/libsystemd-id128.pc
ln -sf ./libsystemd.pc %{buildroot}%{_libdir}/pkgconfig/libsystemd-journal.pc
ln -sf ./libsystemd.pc %{buildroot}%{_libdir}/pkgconfig/libsystemd-login.pc

# end of install
%pre
/usr/bin/getent group cdrom >/dev/null 2>&1 || /usr/sbin/groupadd -r -g 11 cdrom >/dev/null 2>&1 || :
/usr/bin/getent group tape >/dev/null 2>&1 || /usr/sbin/groupadd -r -g 33 tape >/dev/null 2>&1 || :
/usr/bin/getent group dialout >/dev/null 2>&1 || /usr/sbin/groupadd -r -g 18 dialout >/dev/null 2>&1 || :
/usr/bin/getent group floppy >/dev/null 2>&1 || /usr/sbin/groupadd -r -g 19 floppy >/dev/null 2>&1 || :
/usr/bin/systemctl stop systemd-udevd-control.socket systemd-udevd-kernel.socket systemd-udevd.service >/dev/null 2>&1 || :

# Rename configuration files that changed their names
/usr/bin/mv -n %{_sysconfdir}/systemd/systemd-logind.conf %{_sysconfdir}/systemd/logind.conf >/dev/null 2>&1 || :
/usr/bin/mv -n %{_sysconfdir}/systemd/systemd-journald.conf %{_sysconfdir}/systemd/journald.conf >/dev/null 2>&1 || :

%post
/usr/bin/systemd-machine-id-setup > /dev/null 2>&1 || :
%if %{WITH_RANDOMSEED}
/usr/lib/systemd/systemd-random-seed save > /dev/null 2>&1 || :
%endif
/usr/bin/systemctl daemon-reexec > /dev/null 2>&1 || :
/usr/bin/systemctl start systemd-udevd.service >/dev/null 2>&1 || :
/usr/bin/mkdir -p /etc/systemd/network
/usr/bin/ln -sf /dev/null /etc/systemd/network/99-default.link

# link system, user unit directory in conf dir to opt conf dir
/usr/bin/mkdir -p /opt/etc/systemd
/usr/bin/mv /etc/systemd/system /opt/etc/systemd/system 
/usr/bin/mv /etc/systemd/user /opt/etc/systemd/user
/usr/bin/ln -s ../../opt/etc/systemd/system /etc/systemd/system
/usr/bin/ln -s ../../opt/etc/systemd/user /etc/systemd/user

# Set the smack label of executable binary tools
chsmack %{_bindir}/bootctl -a "System::Tools"
chsmack %{_bindir}/busctl -a "System::Tools"
chsmack %{_bindir}/kernel-install -a "System::Tools"
%if %{?WITH_MACHINED}
chsmack %{_bindir}/machinectl -a "System::Tools"
%endif
chsmack %{_bindir}/systemd-run -a "System::Tools"
%if %{?WITH_HOSTNAMED}
chsmack %{_bindir}/hostnamectl -a "System::Tools"
%endif
chsmack %{_bindir}/localectl -a "System::Tools"
%if %{?WITH_COREDUMP}
chsmack %{_bindir}/coredumpctl -a "System::Tools"
%endif
%if %{?WITH_TIMEDATED}
chsmack %{_bindir}/timedatectl -a "System::Tools"
%endif
chsmack %{_bindir}/systemd -a "System::Tools"
chsmack %{_bindir}/systemctl -a "System::Tools"
chsmack %{_bindir}/systemd-notify -a "System::Tools"
chsmack %{_bindir}/systemd-ask-password -a "System::Tools"
chsmack %{_bindir}/systemd-tty-ask-password-agent -a "System::Tools"
chsmack %{_bindir}/systemd-machine-id-setup -a "System::Tools"
chsmack %{_bindir}/systemd-socket-activate -a "System::Tools"
chsmack %{_bindir}/loginctl -a "System::Tools"
chsmack %{_bindir}/systemd-loginctl -a "System::Tools"
chsmack %{_bindir}/journalctl -a "System::Tools"
chsmack %{_bindir}/systemd-tmpfiles -a "System::Tools"
chsmack %{_bindir}/systemd-nspawn -a "System::Tools"
chsmack %{_bindir}/systemd-stdio-bridge -a "System::Tools"
chsmack %{_bindir}/systemd-cat -a "System::Tools"
chsmack %{_bindir}/systemd-cgls -a "System::Tools"
chsmack %{_bindir}/systemd-cgtop -a "System::Tools"
chsmack %{_bindir}/systemd-delta -a "System::Tools"
chsmack %{_bindir}/systemd-detect-virt -a "System::Tools"
chsmack %{_bindir}/systemd-inhibit -a "System::Tools"
chsmack %{_bindir}/udevadm -a "System::Tools"
chsmack %{_bindir}/systemd-escape -a "System::Tools"
chsmack %{_bindir}/systemd-path -a "System::Tools"
chsmack %{_prefix}/lib/systemd/* -a "System::Tools"

%postun
if [ $1 -ge 1 ] ; then
        /usr/bin/systemctl daemon-reload > /dev/null 2>&1 || :
        /usr/bin/systemctl try-restart systemd-logind.service >/dev/null 2>&1 || :
fi

%preun
if [ $1 -eq 0 ] ; then
        /usr/bin/systemctl disable \
                getty@.service \
                remote-fs.target \
                systemd-readahead-replay.service \
                systemd-readahead-collect.service >/dev/null 2>&1 || :
fi

%post -n libsystemd -p /sbin/ldconfig
%postun -n libsystemd  -p /sbin/ldconfig

%lang_package

%files
%manifest %{name}.manifest
%license LICENSE.LGPL2.1  LICENSE.GPL2
%config %{_sysconfdir}/pam.d/systemd-user
%{_bindir}/bootctl
%{_bindir}/busctl
%{_bindir}/kernel-install
%if %{?WITH_MACHINED}
%{_bindir}/machinectl
%endif
%{_bindir}/systemd-run
%dir %{_prefix}/lib/kernel
%dir %{_prefix}/lib/kernel/install.d
%{_prefix}/lib/kernel/install.d/50-depmod.install
%{_prefix}/lib/kernel/install.d/90-loaderentry.install
%if %{?WITH_HOSTNAMED}
%{_bindir}/hostnamectl
%endif
%{_bindir}/localectl
%if %{?WITH_COREDUMP}
%{_bindir}/coredumpctl
%endif
%if %{?WITH_TIMEDATED}
%{_bindir}/timedatectl
%endif
%dir %{_sysconfdir}/systemd
%{_sysconfdir}/systemd/system
%{_sysconfdir}/systemd/user
%dir %{_sysconfdir}/tmpfiles.d
%dir %{_sysconfdir}/sysctl.d
%dir %{_sysconfdir}/modules-load.d
%dir %{_sysconfdir}/binfmt.d
%if %{?WITH_BASH_COMPLETION}
%{_datadir}/bash-completion/*
%endif
%if %{?WITH_ZSH_COMPLETION}
%dir %{_datadir}/zsh/site-functions
%{_datadir}/zsh/site-functions/*
%endif
%dir %{_sysconfdir}/udev
%dir %{_sysconfdir}/udev/rules.d
%dir %{_prefix}/lib/systemd
%dir %{_prefix}/lib/systemd/system
%dir %{_prefix}/lib/systemd/system-generators
%dir %{_prefix}/lib/systemd/user-generators
%dir %{_prefix}/lib/systemd/system-preset
%dir %{_prefix}/lib/systemd/user-preset
%dir %{_prefix}/lib/systemd/system-shutdown
%dir %{_prefix}/lib/systemd/system-sleep
%dir %{_prefix}/lib/tmpfiles.d
%dir %{_prefix}/lib/sysctl.d
%dir %{_prefix}/lib/modules-load.d
%dir %{_prefix}/lib/binfmt.d
%dir %{_prefix}/lib/firmware
%dir %{_prefix}/lib/firmware/updates
%dir %{_datadir}/systemd
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.systemd1.conf
%if %{?WITH_HOSTNAMED}
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.hostname1.conf
%endif
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.login1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.locale1.conf
%if %{?WITH_TIMEDATED}
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.timedate1.conf
%endif
%if %{?WITH_MACHINED}
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.machine1.conf
%endif
%if %{?WITH_COREDUMP}
%config(noreplace) %{_sysconfdir}/systemd/coredump.conf
%endif
%config(noreplace) %{_sysconfdir}/systemd/system.conf
%config(noreplace) %{_sysconfdir}/systemd/user.conf
%config(noreplace) %{_sysconfdir}/systemd/logind.conf
%config(noreplace) %{_sysconfdir}/systemd/journald.conf
%config(noreplace) %{_sysconfdir}/udev/udev.conf
%{_sysconfdir}/xdg/systemd
%ghost %config(noreplace) %{_sysconfdir}/hostname
%ghost %config(noreplace) %{_sysconfdir}/vconsole.conf
%ghost %config(noreplace) %{_sysconfdir}/locale.conf
%ghost %config(noreplace) %{_sysconfdir}/machine-id
%ghost %config(noreplace) %{_sysconfdir}/machine-info
%ghost %config(noreplace) %{_sysconfdir}/timezone
%exclude %{_sysconfdir}/X11/xinit/xinitrc.d/50-systemd-user.sh
%{_bindir}/systemd
%{_bindir}/systemctl
%{_bindir}/systemd-notify
%{_bindir}/systemd-ask-password
%{_bindir}/systemd-tty-ask-password-agent
%{_bindir}/systemd-machine-id-setup
%{_bindir}/systemd-socket-activate
%{_bindir}/loginctl
%{_bindir}/systemd-loginctl
%{_bindir}/journalctl
%{_bindir}/systemd-tmpfiles
%{_bindir}/systemd-nspawn
%{_bindir}/systemd-stdio-bridge
%{_bindir}/systemd-cat
%{_bindir}/systemd-cgls
%{_bindir}/systemd-cgtop
%{_bindir}/systemd-delta
%{_bindir}/systemd-detect-virt
%{_bindir}/systemd-inhibit
%{_bindir}/udevadm
%{_bindir}/systemd-escape
%{_bindir}/systemd-path
%{_prefix}/lib/sysctl.d/*.conf
%{_prefix}/lib/systemd/systemd
%{_prefix}/lib/systemd/system
%exclude %{_prefix}/lib/systemd/resolv.conf

%dir %{_prefix}/lib/systemd/system/basic.target.wants
%dir %{_prefix}/lib/systemd/user
%dir %{_prefix}/lib/systemd/network
%{_prefix}/lib/systemd/user/basic.target
%{_prefix}/lib/systemd/user/bluetooth.target
%{_prefix}/lib/systemd/user/exit.target
%{_prefix}/lib/systemd/user/printer.target
%{_prefix}/lib/systemd/user/shutdown.target
%{_prefix}/lib/systemd/user/sockets.target
%{_prefix}/lib/systemd/user/sound.target
%{_prefix}/lib/systemd/user/systemd-exit.service
%{_prefix}/lib/systemd/user/paths.target
%{_prefix}/lib/systemd/user/smartcard.target
%{_prefix}/lib/systemd/user/timers.target
%exclude %{_prefix}/lib/systemd/network/80-container-ve.network
%exclude %{_prefix}/lib/systemd/network/80-container-host0.network
%exclude %{_prefix}/lib/systemd/network/80-container-vz.network
%{_prefix}/lib/systemd/user/default.target
%{_prefix}/lib/systemd/network/99-default.link
%exclude %{_prefix}/lib/systemd/system-preset/90-systemd.preset

%{_prefix}/lib/systemd/libsystemd-shared-231.so
%{_prefix}/lib/systemd/libsystemd-shared.so
%{_prefix}/lib/systemd/systemd-*
%dir %{_prefix}/lib/systemd/catalog
%{_prefix}/lib/systemd/catalog/systemd.catalog
%{_prefix}/lib/udev
%{_prefix}/lib/systemd/system-generators/systemd-getty-generator
%{_prefix}/lib/systemd/system-generators/systemd-fstab-generator
%{_prefix}/lib/systemd/system-generators/systemd-system-update-generator
%{_prefix}/lib/tmpfiles.d/home.conf
%{_prefix}/lib/tmpfiles.d/journal-nocow.conf
%{_prefix}/lib/tmpfiles.d/legacy.conf
%{_prefix}/lib/tmpfiles.d/pamconsole-tmp.conf
%{_prefix}/lib/tmpfiles.d/systemd.conf
%{_prefix}/lib/tmpfiles.d/systemd-nologin.conf
%{_prefix}/lib/tmpfiles.d/systemd-nspawn.conf
%{_prefix}/lib/tmpfiles.d/tmp.conf
%{_prefix}/lib/tmpfiles.d/var.conf
%{_prefix}/lib/tmpfiles.d/x11.conf
%{_sbindir}/init
%{_sbindir}/reboot
%{_sbindir}/halt
%{_sbindir}/poweroff
%{_sbindir}/shutdown
%{_sbindir}/telinit
%{_sbindir}/runlevel
%{_sbindir}/udevadm
%{_datadir}/systemd/graphinfo.gvpr
%{_datadir}/systemd/kbd-model-map
%{_datadir}/systemd/language-fallback-map
%{_datadir}/dbus-1/services/org.freedesktop.systemd1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.systemd1.service
%if %{?WITH_HOSTNAMED}
%{_datadir}/dbus-1/system-services/org.freedesktop.hostname1.service
%endif
%{_datadir}/dbus-1/system-services/org.freedesktop.login1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.locale1.service
%if %{?WITH_TIMEDATED}
%{_datadir}/dbus-1/system-services/org.freedesktop.timedate1.service
%endif
%if %{?WITH_MACHINED}
%{_datadir}/dbus-1/system-services/org.freedesktop.machine1.service
%endif
%dir %{_datadir}/factory/
%dir %{_datadir}/factory/etc
%dir %{_datadir}/factory/etc/pam.d
%{_datadir}/factory/etc/nsswitch.conf
%{_datadir}/factory/etc/pam.d/other
%{_datadir}/factory/etc/pam.d/system-auth

%{_localstatedir}/log/journal

%files -n libsystemd
%manifest %{name}.manifest
%license LICENSE.LGPL2.1
%{_libdir}/security/pam_systemd.so
%{_libdir}/libsystemd.so.*
%{_libdir}/libudev.so.*
%{_libdir}/libnss_myhostname.so.2
%if %{?WITH_MACHINED}
%{_libdir}/libnss_mymachines.so.2
%endif

%files extension-kdbus
%manifest %{name}.manifest
%license LICENSE.LGPL2.1  LICENSE.GPL2
%{_sysconfdir}/systemd/extension-kdbus
%{_prefix}/lib/systemd/user/busnames.target
%{_prefix}/lib/systemd/system-generators/systemd-dbus1-generator
%{_prefix}/lib/systemd/user-generators/systemd-dbus1-generator

%files devel
%manifest %{name}.manifest
%{_libdir}/libudev.so
%{_libdir}/libsystemd.so
%dir %{_includedir}/systemd
%{_includedir}/systemd/sd-bus.h
%{_includedir}/systemd/sd-bus-protocol.h
%{_includedir}/systemd/sd-bus-vtable.h
%{_includedir}/systemd/sd-event.h
%{_includedir}/systemd/_sd-common.h
%{_includedir}/systemd/sd-daemon.h
%{_includedir}/systemd/sd-id128.h
%{_includedir}/systemd/sd-journal.h
%{_includedir}/systemd/sd-login.h
%{_includedir}/systemd/sd-messages.h
%{_includedir}/libudev.h
%{_libdir}/pkgconfig/libudev.pc
%{_libdir}/pkgconfig/libsystemd.pc
%{_datadir}/pkgconfig/systemd.pc
%{_datadir}/pkgconfig/udev.pc
%{_libdir}/pkgconfig/libsystemd-daemon.pc
%{_libdir}/pkgconfig/libsystemd-id128.pc
%{_libdir}/pkgconfig/libsystemd-journal.pc
%{_libdir}/pkgconfig/libsystemd-login.pc
%{_sysconfdir}/rpm/macros.systemd

%files analyze
%manifest %{name}.manifest
%license LICENSE.LGPL2.1
%{_bindir}/systemd-analyze

%files tests
%manifest %{name}.manifest
%{_prefix}/lib/dbus-tests/test-suites/systemd-tests/
%{_prefix}/lib/dbus-tests/runner/systemd-tests

%if %{?WITH_DOC}
%docs_package
%endif
