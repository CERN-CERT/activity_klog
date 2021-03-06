%{!?dist: %define dist .slc6}
%define debug_package %{nil}

Name:		activity_klog
Version:	3.6
Release:	1%{?dist}

Summary:	Kernel modules for logging various user activity
Group:		System Environment/Kernel
License:	GPLv2+
URL:		http://github.com/CERN-CERT/activity_klog
Vendor:		CERN, http://cern.ch/linux
BuildRoot:	%{_tmppath}/%{name}-%{version}-buildroot
BuildRequires:	sed, redhat-rpm-config
BuildRequires:	%kernel_module_package_buildreqs
%if 0%rhel >= 7
BuildRequires:	checkpolicy, selinux-policy-devel
BuildRequires:	hardlink
%endif
ExclusiveArch:	i686 x86_64

Source0:	%{name}-%{version}.tgz
Source1:	%{name}-config-%{version}.tgz
Source2:	%{name}-selinux-%{version}.tgz
Source3:	secure_log.files
Source4:	netlog.files
Source5:	execlog.files
Source6:	secure_log.preamble

# Build only for standard kernel variant(s)
%if 0%rhel >= 7
%kernel_module_package -f %{SOURCE3} -p %{SOURCE6} -n secure_log default
%endif
%kernel_module_package -f %{SOURCE4} -n netlog default
%kernel_module_package -f %{SOURCE5} -n execlog default

%if 0%rhel >= 7
%define modules_to_build netlog execlog secure_log
%else
%define modules_to_build netlog execlog
%endif


# Build only the following SELinux variant(s)
%global selinux_variants targeted

%description
%{name} is a collection of Loadable Kernel Modules for logging various user activity

%if 0%rhel >= 7
%package -n secure_log-selinux
Summary:	Selinux module for secure_log kernel module
Group:		System Environment/Kernel
Requires:	selinux-policy
Requires(post):	/usr/sbin/semodule, /sbin/restorecon, /sbin/fixfiles
Requires(postun):	/usr/sbin/semodule, /sbin/restorecon, /sbin/fixfiles

%description -n secure_log-selinux
Simple selinux policy for kmod-secure_log
It allows syslogd to read directly from the newly created device
%endif

%prep
%setup -q
set -- *
%if 0%rhel == 6
# Enable compat features
echo "ccflags-y += -DUSE_PRINK=1" >> execlog/Kbuild
echo "ccflags-y += -DUSE_PRINK=1" >> netlog/Kbuild
sed -i "s/^src_files = \(.*\)/src_files = \1 print_netlog.c/" netlog/Kbuild
# Disable secure_log
sed '/secure_log/d' -i Kbuild
%endif
mkdir source
mv "$@" source/
mkdir obj
%setup -q -T -D -a 1
%setup -q -T -D -a 2

%build
for flavor in %flavors_to_build ; do
	rm -rf obj/$flavor
	cp -r source obj/$flavor

	# update symvers file if existing
	symvers=source/Module.symvers-%{_target_cpu}
	if [ -e $symvers ]; then
		cp $symvers obj/$flavor/Module.symvers
	fi

	make -C %{kernel_source $flavor} M=$PWD/obj/$flavor \
	MOD_VER=%{version}
done
%if 0%rhel >= 7
#Selinux
cd SELinux
for selinuxvariant in %{selinux_variants}
do
	make NAME=${selinuxvariant} -f /usr/share/selinux/devel/Makefile
	mv secure_log.pp secure_log.pp.${selinuxvariant}
	make NAME=${selinuxvariant} -f /usr/share/selinux/devel/Makefile clean
done
%endif
cd -

%install
rm -rf $RPM_BUILD_ROOT
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=extra/
for flavor in %flavors_to_build ; do 
	make -C %{kernel_source $flavor} modules_install \
	M=$PWD/obj/$flavor module_version=%{version}

	# Cleanup unnecessary kernel-generated module dependency files.
	find $INSTALL_MOD_PATH/lib/modules -iname 'modules.*' -exec rm {} \;
done

mkdir -p ${RPM_BUILD_ROOT}/etc/depmod.d/
for module in %{modules_to_build}; do
	install -m0644 config/${module}.conf $RPM_BUILD_ROOT/etc/depmod.d/
done

#Load at boot time
mkdir -p ${RPM_BUILD_ROOT}/etc/sysconfig/modules/
for module in netlog execlog; do
	install -m0755 config/${module}.modules ${RPM_BUILD_ROOT}/etc/sysconfig/modules/
done

%if 0%rhel >= 7
#Selinux
for selinuxvariant in %{selinux_variants}
do
	install -d %{buildroot}%{_datadir}/selinux/${selinuxvariant}
	install -p -m 644 SELinux/secure_log.pp.${selinuxvariant} \
		%{buildroot}%{_datadir}/selinux/${selinuxvariant}/secure_log.pp
done
/usr/sbin/hardlink -cv %{buildroot}%{_datadir}/selinux

# Udev rule
mkdir -p  ${RPM_BUILD_ROOT}/etc/udev/rules.d/
install -m0644 config/secure_log.udev ${RPM_BUILD_ROOT}/etc/udev/rules.d/99-securelog.rules

%files -n secure_log-selinux
%defattr(644,root,root,755)
%{_datadir}/selinux/*/secure_log.pp
/etc/udev/rules.d/99-securelog.rules

%post -n secure_log-selinux
for selinuxvariant in %{selinux_variants}; do
	/usr/sbin/semodule -s ${selinuxvariant} -i \
		%{_datadir}/selinux/${selinuxvariant}/secure_log.pp &> /dev/null || :
done
[ -c /dev/secure_log ] && /sbin/restorecon /dev/secure_log

%postun -n secure_log-selinux
if [ $1 -eq 0 ] ; then
	for selinuxvariant in %{selinux_variants}; do
		/usr/sbin/semodule -s ${selinuxvariant} -r secure_log &> /dev/null || :
	done
fi
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%changelog
* Wed Jul 11 2018 Vincent Brillault <vincent.brillault@cern.ch> - 3.6-1
- Execlog: fix an off-by-one overflow when truncating argv
- Ensure RCU protected fields are properly dereferenced
- Execlog: extract real executable path when possible
- Exelog: add a parameter to control argv truncation

* Fri May 25 2018 Vincent Brillault <vincent.brillault@cern.ch> - 3.5-3
- Rebuild for Centos 7.5 (retpoline)

* Thu Aug 24 2017 Vincent Brillault <vincent.brillault@cern.ch> - 3.5-2
- Rebuild for Centos 7.4 (d_path symbol version change)

* Tue Apr 11 2017 Vincent Brillault <vincent.brillault@cern.ch> - 3.5-1
- Remove leading space in secure_log 'simple' timestamp format

* Mon Apr 10 2017 Vincent Brillault <vincent.brillault@cern.ch> - 3.4-1
- Fix out-of-bound access in memory allocation failure path
- Better handling of truncated input

* Wed Dec 07 2016 Vincent Brillault <vincent.brillault@cern.ch> - 3.3-2
- Wrong version variable set in the spec file

* Wed Oct 26 2016 Vincent Brillault <vincent.brillault@cern.ch> - 3.3-1
- Ensure that module parameter 'version' is kept up to date
- Remove duplicated pr_fmt definition

* Tue Aug 16 2016 Vincent Brillault <vincent.brillault@cern.ch> - 3.2-1
- Better fix for buffer wrapping, pulling code from upstream

* Wed Jul 20 2016 Vincent Brillault <vincent.brillault@cern.ch> - 3.1-1
- Fix index reset error on buffer wrapping, leading to kernel panic
- Properly align log records in secure_log

* Mon May 23 2016 Vincent Brillault <vincent.brillault@cern.ch> - 3.0-6
- Refactor execlog module into separate parts
- Introduce whitelist feature for execlog, based on merged netlog code
- Remove old configuration option via /proc for netlog
- Remove broken "WHITELISTING" build option
- Delay probe loading at initialization

* Fri Mar 18 2016 Vincent Brillault <vincent.brillault@cern.ch> - 2.10-1
- Execlog: limit printk messages to less than 1000 chars

* Mon Feb 08 2016 Vincent Brillault <vincent.brillault@cern.ch> - 2.9-1
- Replace new lines with space

* Tue Apr 14 2015 Vincent Brillault <vincent.brillault@cern.ch> - 2.8-3
- Re-release: last version compiled with wrong sources

* Mon Mar 23 2015 Vincent Brillault <vincent.brillault@cern.ch> - 2.8-2
- Bugfix: revert a1946c6335adee2b0c78ed118928dcdaca701834

* Wed Mar 04 2015 Vincent Brillault <vincent.brillault@cern.ch> - 2.8
- Log kernel uids/gids instead of the ones inside namespaces
- Fix some locking/atomic issues
- Better logs for error cases
- Add support for compilation time checks with clang
- Code cleaning and multiple minor issues

* Fri Nov 21 2014 Vincent Brillault <vincent.brillault@cern.ch> - 2.7
- Fix netlog action decoding table

* Thu Jul 24 2014 Vincent Brillault <vincent.brillault@cern.ch> - 2.6
- Adapt code to Centos 7
- Netlog: do not disable irq when planting probes
- Execlog: monitor compat_sys_execve
- Execlog: delay argv copying (avoid page faults)
- Project reorganisation (use logical links)

* Thu Jul 10 2014 Vincent Brillault <vincent.brillault@cern.ch> - 2.5
- Add backward compatibility with netlog version 1

* Thu Mar 27 2014 Vincent Brillault <vincent.brillault@cern.ch> - 2.4_rc1
- Enhanced rsyslog support (send_eof)
- Fix buffer overflow in sercure_log

* Thu Mar 20 2014 Vincent Brillault <vincent.brillault@cern.ch> - 2.3_rc2
- Remove mls support: not supported in SLC
- Typo in configuration

* Fri Mar 14 2014 Vincent Brillault <vincent.brillault@cern.ch> - 2.3_rc1
- Info/Error info cleaning
- Use kret pre-handler instead of jprobe: use kretprobe local cache instead of global cache
- Small code simplification

* Wed Mar 12 2014 Vincent Brillault <vincent.brillault@cern.ch> - 2.2_rc2
- Fix specfile (loading wrong module, cleaning)
- Create a dedicated package for selinux, depend on it
- Adapt netlog to linux 3.13
- Only accept hexadecimal for 'probes' parameter

* Wed Mar 05 2014 Vincent Brillault <vincent.brillault@cern.ch> - 2.2_rc1
- Replace procfs folders/files by kernel modules parameters

* Wed Feb 26 2014 Vincent Brillault <vincent.brillault@cern.ch> - 2.1_rc2
- Add SELinux support
- Add Rsyslog support for secure_log (simpler format)
- Bugfixes

* Tue Jan 07 2014 Vincent Brillault <vincent.brillault@cern.ch> - 2.1_rc1
- Import of a major rewrite from fork github.com/Feandil
- Rewrite of spec file (multiple packages)

* Wed Sep 19 2012 Panos Sakkos <panos.sakkos@cern.ch> - 1.30
- Updated version to 1.30, which introduces the "On the fly whitelisting" feature.

* Wed Sep 12 2012 Antonio Perez <antonio.perez.perez@cern.ch> - 1.23-2
- Fixed and cleaned the Makefile and spec file.

* Fri Jul 20 2012 Panos Sakkos <panos.sakkos@cern.ch> - 1.23-1
- Fixes for the deployment

* Fri Mar 23 2012 Jaroslaw Polok <jaroslaw.polok@cern.ch> - 1.5
- updated to latest.

* Fri Mar 16 2012 Jaroslaw Polok <jaroslaw.polok@cern.ch> - 1.4
- changed packaging for SLC6, following RHEL6 kmod packaging.
