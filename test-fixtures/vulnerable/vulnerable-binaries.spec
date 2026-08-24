Name: binaryscan-vulnerable-binaries
Version: 1.0
Release: 1
Summary: BinaryScan offline archive fixture
License: Public-Domain
BuildArch: x86_64
Source0: vulnerable-elf

%description
Synthetic package containing one intentionally unsafe ELF for static-analysis regression.

%prep

%build

%install
mkdir -p %{buildroot}/usr/bin
install -m 0755 %{SOURCE0} %{buildroot}/usr/bin/vulnerable-elf

%files
/usr/bin/vulnerable-elf
