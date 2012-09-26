%{!?dist: %define dist .ai6}
%define debug_package %{nil}

Name:		netlog
Version:	1.30
Release:	1%{?dist}

Summary:	Kernel module for logging network connections details
Group:		System Environment/Kernel
License:	GPLv2+
URL:		http://github.com/CERN-CERT/netlog
Vendor:		CERN, http://cern.ch/linux
BuildRoot: 	%{_tmppath}/%{name}-%{version}-buildroot
BuildRequires:	sed, redhat-rpm-config
BuildRequires:	%kernel_module_package_buildreqs
ExclusiveArch:	i686 x86_64

Source0:	%{name}/%{name}-%{version}.tar.gz
Source1:	%{name}.files
Source2:	%{name}.conf
Source3:	%{name}.modules

# Uncomment to build "debug" packages
#kernel_module_package -f %{SOURCE1} default debug

# Build only for standard kernel variant(s)
%kernel_module_package -f %{SOURCE1} default

%description
%{name} is a Loadable Kernel Module that logs information for every connection.

%prep
%setup -q
set -- *
mkdir source
mv "$@" source/
mkdir obj

%build
for flavor in %flavors_to_build ; do
	rm -rf obj/$flavor
	cp -r source obj/$flavor

	# update symvers file if existing
	symvers=source/Module.symvers-%{_target_cpu}
	if [ -e $symvers ]; then
		cp $symvers obj/$flavor/Module.symvers
	fi

	make -C %{kernel_source $flavor} M=$PWD/obj/$flavor/src
done


# We don't need this as the config files are already provided with the kmod-%{name} 
# package. 

#%files
#%defattr(644,root,root,755)
#/etc/depmod.d/netlog.conf
#%config(noreplace) %attr(0755,root,root) /etc/sysconfig/modules/%{name}.modules


%install
rm -rf $RPM_BUILD_ROOT
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=extra/%{name}
for flavor in %flavors_to_build ; do 
	 make -C %{kernel_source $flavor} modules_install \
	 M=$PWD/obj/$flavor/src
	# Cleanup unnecessary kernel-generated module dependency files.
	find $INSTALL_MOD_PATH/lib/modules -iname 'modules.*' -exec rm {} \;
done

install -m644 -D %{SOURCE2} $RPM_BUILD_ROOT/etc/depmod.d/%{name}.conf

#Load at boot time

mkdir -p ${RPM_BUILD_ROOT}/etc/sysconfig/modules/
install -m0755 %{SOURCE3} ${RPM_BUILD_ROOT}/etc/sysconfig/modules/

%post

${RPM_BUILD_ROOT}/etc/sysconfig/modules/%{name}.modules

%clean
rm -rf $RPM_BUILD_ROOT

%changelog
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
