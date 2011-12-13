Name: netlog
License: GPL
Group: System/Kernel
Summary: Logs TCP connections
Version: 1.0
Release: 0
#Source0: %name-%version.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-build
BuildRequires: %kernel_module_package_buildreqs
%kernel_module_package

%description
TODO

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
* Tue Dec  13 2011 Panos Sakkos 
- Updated original examples
