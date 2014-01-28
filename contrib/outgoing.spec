%define  debug_package %{nil}
%global __strip /bin/true
%global rev 331e86ecf4e71358e9fb7628a92fcb17380fa70b
%global shortrev %(r=%{rev}; echo ${r:0:12})

Name: outgoing-redirector
Version: 0.0.1
Release: r1.%{shortrev}%{?dist}
Summary: Redirects outgoing urls.

License: MPL
URL: https://github.com/oremj/outgoing
Source0: outgoing-redirector-%{version}.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)


%description
Outgoing link redirector.

%prep
%setup -q -n outgoing-master

%build
go build -o outgoing


%install
rm -rf %{buildroot}
install -d %{buildroot}%{_bindir}
ls
install ./outgoing %{buildroot}%{_bindir}/outgoing-redirector


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{_bindir}/outgoing-redirector

%changelog

