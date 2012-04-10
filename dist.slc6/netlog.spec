%define kmod_name		netlog
%define kmod_driver_version	1.7
%define kmod_rpm_release	1
%define kmod_kernel_version	2.6.32-220.7.1.el6

# with koji ... we have to build against current (newest) kernel ...

%{!?dist: %define dist .slc6}

Source0: %{kmod_name}-%{kmod_driver_version}.tgz
Source1: %{kmod_name}.files
Source2: %{kmod_name}.conf
Source4: kmodtool-%{kmod_name}

Name: %{kmod_name}
Version: %{kmod_driver_version}
Release: %{kmod_rpm_release}%{?dist}
Summary: %{kmod_name} kernel module       
Group:   System/Kernel
License: GPL
URL:     http://www.cern.ch/
Vendor: CERN, http://cern.ch/linux
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires:  sed
BuildRequires:	%kernel_module_package_buildreqs
ExclusiveArch:  i686 x86_64

# Uncomment to build "debug" packages
#kernel_module_package -f %{SOURCE1} default debug

# Build only for standard kernel variant(s)
%kernel_module_package -s %{SOURCE4} -f %{SOURCE1} default

%description
%{kmod_name} is a Loadable Kernel Module that logs information for every connection.

%prep
%setup
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

   make -C %{kernel_source $flavor} M=$PWD/obj/$flavor
done

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=extra/%{kmod_name}
for flavor in %flavors_to_build ; do 
   make -C %{kernel_source $flavor} modules_install \
     M=$PWD/obj/$flavor
  # Cleanup unnecessary kernel-generated module dependency files.
	find $INSTALL_MOD_PATH/lib/modules -iname 'modules.*' -exec rm {} \;
done

install -m644 -D %{SOURCE2} $RPM_BUILD_ROOT/etc/depmod.d/%{kmod_name}.conf

%clean
rm -rf $RPM_BUILD_ROOT

%changelog
* Fri Mar 23 2012 Jaroslaw Polok <jaroslaw.polok@cern.ch> - 1.5
- updated to latest.

* Fri Mar 16 2012 Jaroslaw Polok <jaroslaw.polok@cern.ch> - 1.4
- changed packaging for SLC6, following RHEL6 kmod packaging.
