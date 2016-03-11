%define kmod_name		ip_vs_ca
%define kmod_version		0.01
%define kmod_release		1%{?dist}

Source0:	ip_vs_ca.tar.bz2
Source10:	ip_vs_ca-kmodtool.sh
#Source100:	patches.v3.14.tar.bz2
Name:           %{kmod_name}
Version:        %{kmod_version}
Release:        %{kmod_release}
Group:          System Environment/Kernel
License:        GPL
Summary:        get ip vs(fullnat) client addr
URL:            http://github.com/yubo/ip_vs_ca
BuildRequires:  %kernel_module_package_buildreqs kernel-abi-whitelists
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
ExclusiveArch:  i686 x86_64

%files
%defattr(-,root,root,-)

#Because redhat-rpm-config is hopelessly broken in chroot environments
%define kversion %{expand:%(sh %{SOURCE10} verrel)}
%{expand:%(sh %{SOURCE10} rpmtemplate %{kmod_name} %{kversion} "")}

%define debug_package %{nil}

%description
get ip vs(fullnat) client addr

%prep
%setup -q -c -T -a 0

%build
ksrc="%{_usrsrc}/kernels/%{kversion}"
%{__make} -C "$ksrc" %{?_smp_mflags} CONFIG_IP_VS_CA=m M=$PWD/ip_vs_ca

%install
%{__install} -d %{buildroot}/lib/modules/%{kversion}/extra/%{kmod_name}/
%{__install} $PWD/ip_vs_ca/*.ko %{buildroot}/lib/modules/%{kversion}/extra/%{kmod_name}/
%{__rm} -f %{buildroot}/lib/modules/%{kversion}/modules.*

%clean
%{__rm} -rf %{buildroot}

%changelog
* Fri Mar 11 2016 Yu Bo <yubo@yubo.org>
- Initial version for RHEL7



