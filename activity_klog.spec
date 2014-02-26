%{!?dist: %define dist .ai6}
%define debug_package %{nil}

Name:		activity_klog
Version:	2.1
Release:	1%{?dist}

Summary:	Kernel modules for logging various user activity
Group:		System Environment/Kernel
License:	GPLv2+
URL:		http://github.com/Feandil/activity_klog
Vendor:		CERN, http://cern.ch/linux
BuildRoot:	%{_tmppath}/%{name}-%{version}-buildroot
BuildRequires:	sed, redhat-rpm-config
BuildRequires:	%kernel_module_package_buildreqs
BuildRequires: hardlink
ExclusiveArch:	i686 x86_64

Source0:	%{name}-%{version}.tgz
Source1:	%{name}-config-%{version}.tgz
Source2:	%{name}-selinux-%{version}.tgz
Source3:	secure_log.files
Source4:	netlog.files
Source5:	execlog.files

# Build only for standard kernel variant(s)
%kernel_module_package -f %{SOURCE3} -n secure_log default
%kernel_module_package -f %{SOURCE4} -n netlog default
%kernel_module_package -f %{SOURCE5} -n execlog default

# Build only the following SELinux variant(s)
%global selinux_variants mls targeted

%description
%{name} is a collection of Loadable Kernel Modules for logging various user activity

%package secure_log
Summary:	Kernel module creating a new logging device
Group:		System Environment/Kernel

%description secure_log
secure_log is a Loadable Kernel Module that create a new logging device
It enables other modules to produce logs that will not go through the standard log device.

%package netlog
Summary:	Kernel module for logging network connections details
Group:		System Environment/Kernel
Requires:	kmod-secure_log

%description netlog
netlog is a Loadable Kernel Module that logs information for every connection.

%package execlog
Summary:	Kernel module for logging file execution details
Group:		System Environment/Kernel
Requires:	kmod-secure_log

%description execlog
Execlog is a Loadable Kernel Module that logs information for every file execution.

%prep
%setup -q
set -- *
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

	make -C %{kernel_source $flavor} M=$PWD/obj/$flavor
done
#Selinux
cd SELinux
for selinuxvariant in %{selinux_variants}
do
	make NAME=${selinuxvariant} -f /usr/share/selinux/devel/Makefile
	mv secure_log.pp secure_log.pp.${selinuxvariant}
	make NAME=${selinuxvariant} -f /usr/share/selinux/devel/Makefile clean
done
cd -

%install
rm -rf $RPM_BUILD_ROOT
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=extra/
for flavor in %flavors_to_build ; do 
	make -C %{kernel_source $flavor} modules_install \
	M=$PWD/obj/$flavor
done

mkdir -p ${RPM_BUILD_ROOT}/etc/depmod.d/
for module in secure_log netlog execlog; do
	install -m0644 config/${module}.conf $RPM_BUILD_ROOT/etc/depmod.d/
done

#Load at boot time
mkdir -p ${RPM_BUILD_ROOT}/etc/sysconfig/modules/
for module in netlog execlog; do
	install -m0755 config/${module}.modules ${RPM_BUILD_ROOT}/etc/sysconfig/modules/
done

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

%post secure_log
for selinuxvariant in %{selinux_variants}; do
	/usr/sbin/semodule -s ${selinuxvariant} -i \
		%{_datadir}/selinux/${selinuxvariant}/mymodule.pp &> /dev/null || :
done

%post netlog
${RPM_BUILD_ROOT}/etc/sysconfig/modules/netlog.modules

%post execlog
${RPM_BUILD_ROOT}/etc/sysconfig/modules/execlog.modules

%postun secure_log
if [ $1 -eq 0 ] ; then
	for selinuxvariant in %{selinux_variants}; do
		/usr/sbin/semodule -s ${selinuxvariant} -r mymodule &> /dev/null || :
	done
fi

%clean
rm -rf $RPM_BUILD_ROOT

%changelog
* Tue Jan 07 2014 Vincent Brillault <vincent.brillault@cern.ch> - 2.1_rc1
- Import of a major rewrite from fork github.com/Feandil
- Rewrite of spec file (multiple packages)

* Tue Sep 19 2012 Panos Sakkos <panos.sakkos@cern.ch> - 1.30
- Updated version to 1.30, which introduces the "On the fly whitelisting" feature.

* Wed Sep 12 2012 Antonio Perez <antonio.perez.perez@cern.ch> - 1.23-2
- Fixed and cleaned the Makefile and spec file.

* Fri Jul 20 2012 Panos Sakkos <panos.sakkos@cern.ch> - 1.23-1
- Fixes for the deployment

* Fri Mar 23 2012 Jaroslaw Polok <jaroslaw.polok@cern.ch> - 1.5
- updated to latest.

* Fri Mar 16 2012 Jaroslaw Polok <jaroslaw.polok@cern.ch> - 1.4
- changed packaging for SLC6, following RHEL6 kmod packaging.
