Source10: /usr/lib/rpm/redhat/kmodtool
%define   kmodtool sh /usr/lib/rpm/redhat/kmodtool

%{!?kversion: %define kversion %(uname -r)}
# hint: this can be overridden with "--define kversion foo" on rpmbuild, e.g.
# --define "kversion 2.6.18-128.el5"

%define kmod_name netlog
%define kverrel %(%{kmodtool} verrel %{?kversion} 2>/dev/null)

%define upvar ""

%ifarch i686 x86_64 ia64
%define xenvar xen
%endif

%ifarch i686
%define paevar PAE
%endif

%{!?kvariants: %define kvariants %{?upvar} %{?xenvar} %{?paevar}}
# hint: this can be overridden with "--define kvariants foo" on rpmbuild, e.g.
# --define 'kvariants "" PAE'

Name:           %{kmod_name}-kmod
Version:        1.4
Release:        1%{?dist}
Summary:        Netlog is a Loadable Kernel Module that logs information for every connection.
Group:          System Environment/Kernel
License:        GPL
URL:            http://www.cern.ch/
Source0:        %{kmod_name}-%{version}.tgz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:  sed
ExclusiveOS:    linux
ExclusiveArch:  %{ix86} x86_64

%description
Netlog is a Loadable Kernel Module that logs information for every connection.

# magic hidden here:
%{expand:%(%{kmodtool} rpmtemplate_kmp %{kmod_name} %{kverrel} %{kvariants} 2>/dev/null)}

%prep
%setup -q -c -T -a 0
for kvariant in %{kvariants}; do
    cp -a %{kmod_name}-%{version} _kmod_build_$kvariant
done
cd %{kmod_name}-%{version}


%build
[ -n $RPM_BUILD_ROOT -a "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p %{buildroot}

for kvariant in %{kvariants}; do
    ksrc=%{_usrsrc}/kernels/%{kverrel}${kvariant:+-$kvariant}-%{_target_cpu}
    pushd _kmod_build_$kvariant/src
    make -C /lib/modules/$(uname -r)/build M=$PWD
    popd
done

%install
for kvariant in %{kvariants}; do
    ksrc=%{_usrsrc}/kernels/%{kverrel}${kvariant:+-$kvariant}-%{_target_cpu}
    pushd _kmod_build_$kvariant/src
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$(uname -r)/extra 
    cp netlog.ko $RPM_BUILD_ROOT/lib/modules/$(uname -r)/extra 
    popd
done
find ${RPM_BUILD_ROOT} -name *ko > files.list
sed -i -e "s|$RPM_BUILD_ROOT||" files.list

%files -f files.list

%clean
[ -n $RPM_BUILD_ROOT -a "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT


%changelog
