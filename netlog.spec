%{!?kversion: %define kversion %(uname -r)}
# hint: this can be overridden with "--define kversion foo" on rpmbuild, e.g.
# --define "kversion 2.6.18-128.el5"

%define kmod_name netlog

# Define the variants for each architecture.
%define basevar ""
%ifarch i686
%define paevar PAE
%endif
%ifarch i686 x86_64
%define xenvar xen
%endif

#%{!?kvariants: %define kvariants %{?upvar} %{?xenvar} %{?paevar}}
%define kvariants %{?basevar}
# hint: this can be overridden with "--define kvariants foo" on rpmbuild, e.g.
# --define 'kvariants "" PAE'

Name:           %{kmod_name}-kmod
Version:        1.4
Release:        1%{?dist}
Summary:        Netlog is a Loadable Kernel Module that logs information for every connection.
Group:          System Environment/Kernel
License:        GPL
URL:            http://www.cern.ch/
Source10:       kmodtool-netlog.sh
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:  sed
ExclusiveOS:    linux
ExclusiveArch:  %{ix86} x86_64

%description
Netlog is a Loadable Kernel Module that logs information for every connection.

# magic hidden here:
%{expand:%(sh %{SOURCE10} rpmtemplate_kmp %{kmod_name} %{kversion} %{kvariants} 2>/dev/null)}

# Disable the building of the debug package(s).
%define debug_package %{nil}

# Define the filter.
%define __find_requires sh %{_builddir}/%{buildsubdir}/filter-requires.sh

%prep
mkdir -p %{kmod_name}-%{version}
(cd %{_sourcedir}; tar --exclude .git -chf - *) | (cd %{kmod_name}-%{version} && tar xf -)

%define buildsubdir %{kmod_name}-%{version}
# %setup defines this var normally, but we don't use it

for kvariant in %{kvariants}; do
    cp -a %{kmod_name}-%{version} _kmod_build_$kvariant
done
echo "/usr/lib/rpm/redhat/find-requires | %{__sed} -e '/^ksym.*/d'" > %{kmod_name}-%{version}/filter-requires.sh
echo "override %{kmod_name} * weak-updates/%{kmod_name}" > kmod-%{kmod_name}.conf


%build
for kvariant in %{kvariants} ; do
    KSRC=%{_usrsrc}/kernels/%{kversion}${kvariant:+-$kvariant}-%{_target_cpu}
    %{__make} -C "${KSRC}" %{?_smp_mflags} modules M=$PWD/_kmod_build_$kvariant
done

%install
%{__rm} -rf %{buildroot}
export INSTALL_MOD_PATH=%{buildroot}
export INSTALL_MOD_DIR=extra/%{kmod_name}
for kvariant in %{kvariants} ; do
    KSRC=%{_usrsrc}/kernels/%{kversion}${kvariant:+-$kvariant}-%{_target_cpu}
    %{__make} -C "${KSRC}" modules_install M=$PWD/_kmod_build_$kvariant
done
%{__install} -d %{buildroot}%{_sysconfdir}/depmod.d/
%{__install} kmod-%{kmod_name}.conf %{buildroot}%{_sysconfdir}/depmod.d/
# Set the module(s) to be executable, so that they will be stripped when packaged.
find %{buildroot} -type f -name \*.ko -exec %{__chmod} u+x \{\} \;

%clean
%{__rm} -rf %{buildroot}


%changelog
