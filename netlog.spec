%{!?kversion: %define kversion %(uname -r)}
# hint: this can be overridden with "--define kversion foo" on rpmbuild, e.g.
# --define "kversion 2.6.18-128.el5"

Name:           netlog
Version:        1.4
Release:        2%{?dist}
Summary:        Netlog is a Loadable Kernel Module that logs information for every connection.
Group:          System Environment/Kernel
License:        GPL
URL:            http://www.cern.ch/
#Source0:        netlog.tar.gz
Source10:       kmodtool-netlog.sh
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:  sed
ExclusiveOS:    linux
ExclusiveArch:  %{ix86} x86_64

BuildRequires: redhat-rpm-config

%description
Netlog is a Loadable Kernel Module that logs information for every connection.

%define kmod_name    %{name}
%define kmod_version %{version}
%define kmod_release %{release}

# magic hidden here:
%{expand:%(sh %{SOURCE10} rpmtemplate %{kmod_name} %{kversion} "")}

# Define kernel source dir (it differs between el5 and el6)
%define __ksrc_base__ %{_usrsrc}/kernels/%{kversion}
%define __ksrc__ %(if [ -d %{__ksrc_base__} ]; then echo %{__ksrc_base__}; else echo %{__ksrc_base__}-%{_target_cpu}; fi)

# Disable the building of the debug package(s).
%define debug_package %{nil}

# Define the filter.
%define __find_requires sh %{_builddir}/filter-requires.sh

%prep
(cd %{_sourcedir}; tar --exclude .git -chf - *) | tar xf -

echo "/usr/lib/rpm/redhat/find-requires | %{__sed} -e '/^ksym.*/d'" > filter-requires.sh
echo "override %{kmod_name} * weak-updates/%{kmod_name}" > kmod-%{kmod_name}.conf


%build
KSRC=%{__ksrc__}
%{__make} -C "${KSRC}" %{?_smp_mflags} modules M=$PWD

%install
%{__rm} -rf %{buildroot}
export INSTALL_MOD_PATH=%{buildroot}
export INSTALL_MOD_DIR=extra/%{kmod_name}
KSRC=%{__ksrc__}
%{__make} -C "${KSRC}" modules_install M=$PWD
%{__install} -d %{buildroot}%{_sysconfdir}/depmod.d/
%{__install} kmod-%{kmod_name}.conf %{buildroot}%{_sysconfdir}/depmod.d/
# Set the module(s) to be executable, so that they will be stripped when packaged.
find %{buildroot} -type f -name \*.ko -exec %{__chmod} u+x \{\} \;

%clean
%{__rm} -rf %{buildroot}


%changelog
