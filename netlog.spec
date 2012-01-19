Name: netlog
License: GPL
Group: System/Kernel
Summary: Logs TCP connections
Version: 1.1
Release: 1
Vendor: CERN, http://cern.ch/linux
BuildRoot: %{_tmppath}/%{name}-%{version}-build
BuildRequires: %kernel_module_package_buildreqs
%kernel_module_package

%description
Logs process name, pid, uid, source ip, source port, destination ip and destination port
for every TCP connection. Also logs connection close and UDP binds

%prep
(cd %{_sourcedir}; tar --exclude .git -chf - *) | tar xf -
set -- *
mkdir source
mv "$@" source/
mkdir obj

%build
export EXTRA_CFLAGS='-DVERSION=\"%version\"'
for flavor in %flavors_to_build ; do
   rm -rf obj/$flavor
   cp -r source obj/$flavor
   make -C %{kernel_source $flavor} M=$PWD/obj/$flavor
done

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=extra/%{name}
for flavor in %flavors_to_build ; do 
   make -C %{kernel_source $flavor} modules_install \
           M=$PWD/obj/$flavor
done

%clean
rm -rf %{buildroot}

%changelog
* Wed Jan  18 2012 Panos Sakkos 
- Added whitelisting
* Thu Dec  15 2011 Panos Sakkos 
- First RPM release