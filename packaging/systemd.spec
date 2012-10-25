Name:           systemd
Url:            http://www.freedesktop.org/wiki/Software/systemd
Version:        195
Release:        0
# For a breakdown of the licensing, see README
License:        LGPLv2+ and MIT and GPLv2+
Summary:        A System and Service Manager
BuildRequires:  libcap-devel
BuildRequires:  libgcrypt-devel
BuildRequires:  pam-devel
BuildRequires:  dbus-devel
BuildRequires:  libxslt
BuildRequires:  pkgconfig
BuildRequires:  libacl-devel
BuildRequires:  pciutils-devel
BuildRequires:  glib2-devel
BuildRequires:  hwdata
BuildRequires:  usbutils >= 0.82
BuildRequires:  libblkid-devel >= 2.20
BuildRequires:  intltool >= 0.40.0
BuildRequires:  gperf
BuildRequires:  xz-devel
BuildRequires:  libkmod-devel >= 5
Requires(post): coreutils
Requires(post): gawk
Requires(pre):  coreutils
Requires(pre):  /usr/bin/getent
Requires(pre):  /usr/sbin/groupadd
Requires:       dbus
Requires:       hwdata
Requires:       filesystem 
Source0:        http://www.freedesktop.org/software/systemd/%{name}-%{version}.tar.xz

Obsoletes:      SysVinit < 2.86-24, sysvinit < 2.86-24
Provides:       SysVinit = 2.86-24, sysvinit = 2.86-24
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
Summary:        systemd libraries
License:        LGPLv2+ and MIT
Requires:       %{name} = %{version}-%{release}
Obsoletes:      libudev < 183
Obsoletes:      systemd < 185-4
Conflicts:      systemd < 185-4

%description -n libsystemd
Libraries for systemd and udev, as well as the systemd PAM module.

%package devel
Summary:        Development headers for systemd
License:        LGPLv2+ and MIT
Requires:       %{name} = %{version}-%{release}
Provides:       libudev-devel = %{version}
Obsoletes:      libudev-devel < 183

%description devel
Development headers and auxiliary files for developing applications for systemd.


%package analyze
Summary:        Tool for processing systemd profiling information
License:        LGPLv2+
Requires:       %{name} = %{version}-%{release}
Requires:       dbus-python
Requires:       pycairo
# for the systemd-analyze split:
Obsoletes:      systemd < 38-5

%description analyze
'systemd-analyze blame' lists which systemd unit needed how much time to finish
initialization at boot.
'systemd-analyze plot' renders an SVG visualizing the parallel start of units
at boot.

%package -n libgudev
Summary:        Libraries for adding libudev support to applications that use glib
License:        LGPLv2+
Requires:       %{name} = %{version}-%{release}

%description -n libgudev
This package contains the libraries that make it easier to use libudev
functionality from applications that use glib.

%package -n libgudev-devel
Summary:        Header files for adding libudev support to applications that use glib
Requires:       libgudev = %{version}-%{release}
License:        LGPLv2+

%description -n libgudev-devel
This package contains the header and pkg-config files for developing
glib-based applications using libudev functionality.

%prep
%setup -q 

%build
%autogen
%configure \
        --with-distro=other \
        --libexecdir=%{_prefix}/lib \
        --disable-gtk-doc \
	--docdir=%{_docdir}/systemd \
        --disable-static
/usr/bin/make %{?_smp_mflags}

%install
%make_install

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

# Make sure the ghost-ing below works
/usr/bin/touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel2.target
/usr/bin/touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel3.target
/usr/bin/touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel4.target
/usr/bin/touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel5.target

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
/usr/bin/mkdir -p %{buildroot}%{_sysconfdir}/X11/xorg.conf.d
/usr/bin/touch %{buildroot}%{_sysconfdir}/X11/xorg.conf.d/00-keyboard.conf

# Install Fedora default preset policy
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-preset/
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/user-preset/

# Make sure the shutdown/sleep drop-in dirs exist
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-shutdown/
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-sleep/

# Make sure the NTP units dir exists
/usr/bin/mkdir -p %{buildroot}%{_prefix}/lib/systemd/ntp-units.d/


# Install modprobe fragment
/usr/bin/mkdir -p %{buildroot}%{_sysconfdir}/modprobe.d/


# To avoid making life hard for Rawhide-using developers, don't package the
# kernel.core_pattern setting until systemd-coredump is a part of an actual
# systemd release and it's made clear how to get the core dumps out of the
# journal.
/usr/bin/rm -f %{buildroot}%{_prefix}/lib/sysctl.d/coredump.conf


rm -rf %{buildroot}/%{_prefix}/lib/systemd/user/default.target


rm -rf %{buildroot}/%{_docdir}/%{name}
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
/usr/lib/systemd/systemd-random-seed save > /dev/null 2>&1 || :
/usr/bin/systemctl daemon-reexec > /dev/null 2>&1 || :
/usr/bin/systemctl start systemd-udevd.service >/dev/null 2>&1 || :

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

        /usr/bin/rm -f /etc/systemd/system/default.target >/dev/null 2>&1 || :
fi

%post -n libsystemd -p /sbin/ldconfig
%postun -n libsystemd  -p /sbin/ldconfig

%post -n libgudev -p /sbin/ldconfig
%postun -n libgudev -p /sbin/ldconfig


%docs_package

%files
/var/log/README
/etc/init.d/README
%{_bindir}/hostnamectl
%{_bindir}/localectl
%{_bindir}/systemd-coredumpctl
%{_bindir}/timedatectl
%dir %{_sysconfdir}/systemd
%dir %{_sysconfdir}/systemd/system
%dir %{_sysconfdir}/systemd/user
%dir %{_sysconfdir}/tmpfiles.d
%dir %{_sysconfdir}/sysctl.d
%dir %{_sysconfdir}/modules-load.d
%dir %{_sysconfdir}/binfmt.d
%dir %{_sysconfdir}/bash_completion.d
%dir %{_sysconfdir}/udev
%dir %{_sysconfdir}/udev/rules.d
%dir %{_prefix}/lib/systemd
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
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.hostname1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.login1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.locale1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.timedate1.conf
%config(noreplace) %{_sysconfdir}/systemd/system.conf
%config(noreplace) %{_sysconfdir}/systemd/user.conf
%config(noreplace) %{_sysconfdir}/systemd/logind.conf
%config(noreplace) %{_sysconfdir}/systemd/journald.conf
%config(noreplace) %{_sysconfdir}/udev/udev.conf
%{_sysconfdir}/bash_completion.d/systemd-bash-completion.sh
%{_sysconfdir}/rpm/macros.systemd
%{_sysconfdir}/xdg/systemd
%ghost %config(noreplace) %{_sysconfdir}/hostname
%ghost %config(noreplace) %{_sysconfdir}/vconsole.conf
%ghost %config(noreplace) %{_sysconfdir}/locale.conf
%ghost %config(noreplace) %{_sysconfdir}/machine-id
%ghost %config(noreplace) %{_sysconfdir}/machine-info
%ghost %config(noreplace) %{_sysconfdir}/timezone
%ghost %config(noreplace) %{_sysconfdir}/X11/xorg.conf.d/00-keyboard.conf
%{_bindir}/systemd
%{_bindir}/systemctl
%{_bindir}/systemd-notify
%{_bindir}/systemd-ask-password
%{_bindir}/systemd-tty-ask-password-agent
%{_bindir}/systemd-machine-id-setup
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
%{_prefix}/lib/systemd/systemd
%{_prefix}/lib/systemd/system

%{_prefix}/lib/systemd/user/bluetooth.target
%{_prefix}/lib/systemd/user/exit.target
%{_prefix}/lib/systemd/user/printer.target
%{_prefix}/lib/systemd/user/shutdown.target
%{_prefix}/lib/systemd/user/sockets.target
%{_prefix}/lib/systemd/user/sound.target
%{_prefix}/lib/systemd/user/systemd-exit.service

%{_prefix}/lib/systemd/systemd-*
%{_prefix}/lib/udev
%{_prefix}/lib/systemd/system-generators/systemd-getty-generator
%{_prefix}/lib/systemd/system-generators/systemd-fstab-generator
%{_prefix}/lib/systemd/system-generators/systemd-system-update-generator
%{_prefix}/lib/tmpfiles.d/systemd.conf
%{_prefix}/lib/tmpfiles.d/x11.conf
%{_prefix}/lib/tmpfiles.d/legacy.conf
%{_prefix}/lib/tmpfiles.d/tmp.conf
%{_sbindir}/init
%{_sbindir}/reboot
%{_sbindir}/halt
%{_sbindir}/poweroff
%{_sbindir}/shutdown
%{_sbindir}/telinit
%{_sbindir}/runlevel
%{_sbindir}/udevadm
%{_datadir}/systemd/kbd-model-map
%{_datadir}/dbus-1/services/org.freedesktop.systemd1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.systemd1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.hostname1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.login1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.locale1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.timedate1.service
%{_datadir}/dbus-1/interfaces/org.freedesktop.systemd1.*.xml
%{_datadir}/dbus-1/interfaces/org.freedesktop.hostname1.xml
%{_datadir}/dbus-1/interfaces/org.freedesktop.locale1.xml
%{_datadir}/dbus-1/interfaces/org.freedesktop.timedate1.xml
%{_datadir}/polkit-1/actions/org.freedesktop.systemd1.policy
%{_datadir}/polkit-1/actions/org.freedesktop.hostname1.policy
%{_datadir}/polkit-1/actions/org.freedesktop.login1.policy
%{_datadir}/polkit-1/actions/org.freedesktop.locale1.policy
%{_datadir}/polkit-1/actions/org.freedesktop.timedate1.policy
%{_datadir}/pkgconfig/systemd.pc
%{_datadir}/pkgconfig/udev.pc

# Make sure we don't remove runlevel targets from F14 alpha installs,
# but make sure we don't create then anew.
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel2.target
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel3.target
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel4.target
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel5.target

%files -n libsystemd
%{_libdir}/security/pam_systemd.so
%{_libdir}/libsystemd-daemon.so.*
%{_libdir}/libsystemd-login.so.*
%{_libdir}/libsystemd-journal.so.*
%{_libdir}/libsystemd-id128.so.*
%{_libdir}/libudev.so.*

%files devel
%{_libdir}/libsystemd-daemon.so
%{_libdir}/libsystemd-login.so
%{_libdir}/libsystemd-journal.so
%{_libdir}/libsystemd-id128.so
%{_libdir}/libudev.so
%{_includedir}/systemd/sd-daemon.h
%{_includedir}/systemd/sd-login.h
%{_includedir}/systemd/sd-journal.h
%{_includedir}/systemd/sd-id128.h
%{_includedir}/systemd/sd-messages.h
%{_includedir}/systemd/sd-shutdown.h
%{_includedir}/libudev.h
%{_libdir}/pkgconfig/libsystemd-daemon.pc
%{_libdir}/pkgconfig/libsystemd-login.pc
%{_libdir}/pkgconfig/libsystemd-journal.pc
%{_libdir}/pkgconfig/libsystemd-id128.pc
%{_libdir}/pkgconfig/libudev.pc


%files analyze
%{_bindir}/systemd-analyze

%files -n libgudev
%{_libdir}/libgudev-1.0.so.*

%files -n libgudev-devel
%{_libdir}/libgudev-1.0.so
%dir %{_includedir}/gudev-1.0
%dir %{_includedir}/gudev-1.0/gudev
%{_includedir}/gudev-1.0/gudev/*.h
%{_libdir}/pkgconfig/gudev-1.0*

