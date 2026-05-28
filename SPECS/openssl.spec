%global package_speccommit 826189aeb9367cce0cb512e33bb932f3940e2a68
%global usver 3.5.5
%global xsver 1
%global xsrel %{xsver}%{?xscount}%{?xshash}
%global package_srccommit openssl-3.5.5
# For the curious:
# 0.9.8jk + EAP-FAST soversion = 8
# 1.0.0 soversion = 10
# 1.1.0 soversion = 1.1 (same as upstream although presence of some symbols
#                        depends on build configuration options)
# 3.0.0 soversion = 3 (same as upstream)
%define soversion 3

%global _performance_build 1

Summary: Utilities from the general purpose cryptography library with TLS implementation
Name:    openssl
%if 0%{?xenserver} < 9
Epoch:   1
%endif
Version: 3.5.5
Release: %{?xsrel}%{?dist}
Source0: openssl-3.5.5.tar.gz
Patch0: 0002-Add-a-separate-config-file-to-use-for-rpm-installs.patch
Patch1: 0003-RH-Do-not-install-html-docs.patch
Patch2: 0004-RH-apps-ca-fix-md-option-help-text.patch-DROP.patch
Patch3: 0005-RH-Disable-signature-verification-with-bad-digests-R.patch
Patch4: 0006-RH-Add-support-for-PROFILE-SYSTEM-system-default-cip.patch
Patch5: 0009-RH-Drop-weak-curve-definitions-RENAMED-SQUASHED.patch
Patch6: 0010-RH-Disable-explicit-ec-curves.patch
Patch7: 0011-RH-skipped-tests-EC-curves.patch
Patch8: 0012-RH-skip-quic-pairwise.patch
Patch9: 0013-RH-version-aliasing.patch
Patch10: 0014-RH-Export-two-symbols-for-OPENSSL_str-n-casecmp.patch
Patch11: 0015-RH-TMP-KTLS-test-skip.patch
Patch12: 0016-RH-Allow-disabling-of-SHA1-signatures.patch
Patch13: 0051-Backport-upstream-27483-for-PKCS11-needs.patch
Patch14: 0056-Add-targets-to-skip-build-of-non-installable-program.patch
Patch15: pass_ipv6_address_correctly
# Source1: fips-hmacify.sh
Source1: 0001-For-XenServer-8.4-retain-support-for-SHA1-signatures.patch

License: Apache-2.0
URL: http://www.openssl.org/
%if 0%{?xenserver} >= 9
BuildRequires: gcc g++
%else
BuildRequires: devtoolset-11-gcc, devtoolset-11-gcc-c++, devtoolset-11-binutils
%endif
BuildRequires: coreutils, perl-interpreter, sed, zlib-devel, /usr/bin/cmp
BuildRequires: /usr/bin/rename
BuildRequires: /usr/bin/pod2man
BuildRequires: /usr/sbin/sysctl
BuildRequires: perl(Test::Harness), perl(Test::More), perl(Math::BigInt)
BuildRequires: perl(Module::Load::Conditional), perl(File::Temp)
BuildRequires: perl(Time::HiRes), perl(Time::Piece), perl(IPC::Cmd), perl(Pod::Html), perl(Digest::SHA)
BuildRequires: perl(FindBin), perl(lib), perl(File::Compare), perl(File::Copy), perl(bigint)
BuildRequires: git-core
BuildRequires: systemtap-sdt-devel
BuildRequires: perl(ExtUtils::MakeMaker)
BuildRequires: perl(IO::Socket::IP)
Requires: coreutils
Requires: %{name}-libs%{?_isa} = %{?epoch:%{epoch}:}%{version}-%{release}

%description
The OpenSSL toolkit provides support for secure communications between
machines. OpenSSL includes a certificate management tool and shared
libraries which provide various cryptographic algorithms and
protocols.

%package libs
Summary: A general purpose cryptography library with TLS implementation
Requires: ca-certificates >= 2008-5
%if 0%{?xenserver} >= 9
Requires: crypto-policies >= 20180730
%endif

%description libs
OpenSSL is a toolkit for supporting cryptography. The openssl-libs
package contains the libraries that are used by various applications which
support cryptographic algorithms and protocols.

%package devel
Summary: Files for development of applications which will use OpenSSL
Requires: %{name}-libs%{?_isa} = %{?epoch:%{epoch}:}%{version}-%{release}
Requires: pkgconfig

%description devel
OpenSSL is a toolkit for supporting cryptography. The openssl-devel
package contains include files needed to develop applications which
support various cryptographic algorithms and protocols.

%package perl
Summary: Perl scripts provided with OpenSSL
Requires: perl-interpreter
Requires: %{name}-libs%{?_isa} = %{?epoch:%{epoch}:}%{version}-%{release}

%description perl
OpenSSL is a toolkit for supporting cryptography. The openssl-perl
package provides Perl scripts for converting certificates and keys
from other formats to the formats used by the OpenSSL toolkit.

%package test-results
Summary: Results from in build test

%description test-results
Collated set of results from tests run as part of the build phase.

%prep
%autosetup -S git -n %{name}-%{version}
%if 0%{?xenserver} < 9
patch -p1 < %{SOURCE1}
%endif

%build
%if 0%{?xenserver} < 9
source /opt/rh/devtoolset-11/enable
%endif

# Figure out which flags we want to use.
# default
sslarch=%{_os}-%{_target_cpu}
sslflags=enable-ec_nistp_64_gcc_128
%ifarch %{arm}
sslarch=linux-armv4
%endif
ktlsopt=enable-ktls

# Add -Wa,--noexecstack here so that libcrypto's assembler modules will be
# marked as not requiring an executable stack.
# Also add -DPURIFY to make using valgrind with openssl easier as we do not
# want to depend on the uninitialized memory as a source of entropy anyway.
RPM_OPT_FLAGS="$RPM_OPT_FLAGS -Wa,--noexecstack -Wa,--generate-missing-build-notes=yes -DPURIFY $RPM_LD_FLAGS"

export HASHBANGPERL=/usr/bin/perl

# ia64, x86_64, ppc are OK by default
# Configure the build tree.  Override OpenSSL defaults with known-good defaults
# usable on all platforms.  The Configure script already knows to use -fPIC and
# RPM_OPT_FLAGS, so we can skip specifiying them here.
./Configure \
	--prefix=%{_prefix} --openssldir=%{_sysconfdir}/pki/tls ${sslflags} \
%if 0%{?xenserver} >= 9
	--system-ciphers-file=%{_sysconfdir}/crypto-policies/back-ends/opensslcnf.config \
%endif
	zlib enable-camellia enable-seed enable-rfc3779 \
	enable-cms enable-md2 enable-rc5 ${ktlsopt} disable-fips -D_GNU_SOURCE\
	no-mdc2 no-ec2m no-sm2 no-sm4 no-atexit enable-buildtest-c++\
	shared  ${sslarch} $RPM_OPT_FLAGS '-DDEVRANDOM="\"/dev/urandom\""' -DOPENSSL_PEDANTIC_ZEROIZATION\
	-Wl,--allow-multiple-definition


make -s %{?_smp_mflags}

# Clean up the .pc files
for i in libcrypto.pc libssl.pc openssl.pc ; do
  sed -i '/^Libs.private:/{s/-L[^ ]* //;s/-Wl[^ ]* //}' $i
done

%check
# Verify that what was compiled actually works.

# Hack - either enable SCTP AUTH chunks in kernel or disable sctp for check
(sysctl net.sctp.addip_enable=1 && sysctl net.sctp.auth_enable=1) || \
(echo 'Failed to enable SCTP AUTH chunks, disabling SCTP for tests...' &&
 sed '/"msan" => "default",/a\ \ "sctp" => "default",' configdata.pm > configdata.pm.new && \
 touch -r configdata.pm configdata.pm.new && \
 mv -f configdata.pm.new configdata.pm)


OPENSSL_ENABLE_MD5_VERIFY=
export OPENSSL_ENABLE_MD5_VERIFY
OPENSSL_ENABLE_SHA1_SIGNATURES=
export OPENSSL_ENABLE_SHA1_SIGNATURES
OPENSSL_SYSTEM_CIPHERS_OVERRIDE=xyz_nonexistent_file
export OPENSSL_SYSTEM_CIPHERS_OVERRIDE
#embed HMAC into fips provider for test run
#dd if=/dev/zero bs=1 count=32 of=tmp.mac
#objcopy --update-section .rodata1=tmp.mac providers/fips.so providers/fips.so.zeromac
#mv providers/fips.so.zeromac providers/fips.so
#rm tmp.mac
#LD_LIBRARY_PATH=. apps/openssl dgst -binary -sha256 -mac HMAC -macopt hexkey:f4556650ac31d35461610bac4ed81b1a181b2d8a43ea2854cbae22ca74560813 < providers/fips.so > providers/fips.so.hmac
#objcopy --update-section .rodata1=providers/fips.so.hmac providers/fips.so providers/fips.so.mac
#mv providers/fips.so.mac providers/fips.so
# %%{SOURCE1} providers/fips.so

# Disable LTO, build tests, and run them
%define _lto_cflags %{nil}
make -s %{?_smp_mflags} build_programs
make test HARNESS_JOBS=8

mkdir %{buildroot}/testresults
cp -rp test-runs/* %{buildroot}/testresults

%define __provides_exclude_from %{_libdir}/openssl

%install
%if 0%{?xenserver} < 9
source /opt/rh/devtoolset-11/enable
%endif

[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
# Install OpenSSL.
install -d $RPM_BUILD_ROOT{%{_bindir},%{_includedir},%{_libdir},%{_mandir},%{_libdir}/openssl,%{_pkgdocdir}}
%make_install
rename so.%{soversion} so.%{version} $RPM_BUILD_ROOT%{_libdir}/*.so.%{soversion}
for lib in $RPM_BUILD_ROOT%{_libdir}/*.so.%{version} ; do
	chmod 755 ${lib}
	ln -s -f `basename ${lib}` $RPM_BUILD_ROOT%{_libdir}/`basename ${lib} .%{version}`
	ln -s -f `basename ${lib}` $RPM_BUILD_ROOT%{_libdir}/`basename ${lib} .%{version}`.%{soversion}
done
mv rh-openssl.cnf $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.cnf

# Remove static libraries
for lib in $RPM_BUILD_ROOT%{_libdir}/*.a ; do
	rm -f ${lib}
done

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/certs
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.d

# Move runable perl scripts to bindir
mv $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/misc/*.pl $RPM_BUILD_ROOT%{_bindir}
mv $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/misc/tsget $RPM_BUILD_ROOT%{_bindir}

# Rename man pages so that they don't conflict with other system man pages.
pushd $RPM_BUILD_ROOT%{_mandir}
mv man5/config.5ossl man5/openssl.cnf.5
popd

mkdir -m755 $RPM_BUILD_ROOT%{_sysconfdir}/pki/CA
mkdir -m700 $RPM_BUILD_ROOT%{_sysconfdir}/pki/CA/private
mkdir -m755 $RPM_BUILD_ROOT%{_sysconfdir}/pki/CA/certs
mkdir -m755 $RPM_BUILD_ROOT%{_sysconfdir}/pki/CA/crl
mkdir -m755 $RPM_BUILD_ROOT%{_sysconfdir}/pki/CA/newcerts

rm -f $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.cnf.dist
rm -f $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/ct_log_list.cnf.dist

# Determine which arch opensslconf.h is going to try to #include.
basearch=%{_arch}

%files
%{!?_licensedir:%global license %%doc}
%license LICENSE.txt
%doc NEWS.md README.md
%{_bindir}/openssl
%{_mandir}/man1/*
%{_mandir}/man5/*
%{_mandir}/man7/*
%exclude %{_mandir}/man1/*.pl*
%exclude %{_mandir}/man1/tsget*
%exclude %{_docdir}/%{name}/html/*
# %%{_sysconfdir}/pki/tls/fipsmodule.cnf
# Drop cmake files unless we need them
%exclude %{_libdir}/cmake/OpenSSL/*.cmake

%files libs
%{!?_licensedir:%global license %%doc}
%license LICENSE.txt
%dir %{_sysconfdir}/pki/tls
%dir %{_sysconfdir}/pki/tls/certs
%dir %{_sysconfdir}/pki/tls/misc
%dir %{_sysconfdir}/pki/tls/private
%dir %{_sysconfdir}/pki/tls/openssl.d
%config(noreplace) %{_sysconfdir}/pki/tls/openssl.cnf
%config(noreplace) %{_sysconfdir}/pki/tls/ct_log_list.cnf
%attr(0755,root,root) %{_libdir}/libcrypto.so.%{version}
%{_libdir}/libcrypto.so.%{soversion}
%attr(0755,root,root) %{_libdir}/libssl.so.%{version}
%{_libdir}/libssl.so.%{soversion}
%attr(0755,root,root) %{_libdir}/engines-%{soversion}
%attr(0755,root,root) %{_libdir}/ossl-modules

%files devel
%doc CHANGES.md doc/dir-locals.example.el doc/openssl-c-indent.el
%{_prefix}/include/openssl
%{_libdir}/*.so
%{_mandir}/man3/*
%{_libdir}/pkgconfig/*.pc

%files perl
%{_bindir}/c_rehash
%{_bindir}/*.pl
%{_bindir}/tsget
%{_mandir}/man1/*.pl*
%{_mandir}/man1/tsget*
%dir %{_sysconfdir}/pki/CA
%dir %{_sysconfdir}/pki/CA/private
%dir %{_sysconfdir}/pki/CA/certs
%dir %{_sysconfdir}/pki/CA/crl
%dir %{_sysconfdir}/pki/CA/newcerts

%files test-results
/testresults

%ldconfig_scriptlets libs

%changelog
* Mon Mar 02 2026 Mark Syms  <mark.syms@citrix.com> - 1:3.5.5-1
- Update to 3.5.5

* Thu Feb 26 2026 Mark Syms <mark.syms@citrix.com> - 3.5.4-3
- Rebuild

* Thu Feb 26 2026 Mark Syms <mark.syms@citrix.com> - 3.5.4-2
- For XenServer 8.4 retain support for SHA1 signatures

* Thu Oct  2 2025 Mark Syms <mark.syms@citrix.com> - 3.5.4-1
- Update to 3.5.4

* Wed Jan 15 2025 Gerald Elder-Vass <gerald.elder-vass@cloud.com> - 3.0.9-6
- CP-53147: Extract reverted patch from the patch queue for future proofing

* Tue Oct 22 2024 Lin Liu <Lin.Liu01@cloud.com> - 3.0.9-5
- CP-50681: Remove Recommends openssl-pkcs11

* Fri Oct 18 2024 Deli Zhang <deli.zhang@cloud.com> - 3.0.9-4
- CP-50862: Add fips only config file

* Thu Sep 26 2024 Stephen Cheng <stephen.cheng@cloud.com> - 3.0.9-3
- CP-51608: Disable SCTP

* Thu Jul 27 2023 Lin Liu <lin.liu@citrix.com> - 3.0.9-2
- Restore basearch

* Thu Jul 27 2023 Lin Liu <lin.liu@citrix.com> - 3.0.9-1
- First imported release

