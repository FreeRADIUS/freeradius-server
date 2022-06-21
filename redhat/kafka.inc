%package libfreeradius-kafka
Summary: Internal support library for FreeRADIUS modules using librdkafka
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: librdkafka
BuildRequires: librdkafka-devel

%description libfreeradius-kafka
Provides common functions for Kafka production and consumer modules

%files libfreeradius-kafka
%defattr(-,root,root)
%{_libdir}/freeradius/libfreeradius-kafka.so

%package kafka
Summary: Kafka producer support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: librdkafka
Requires: freeradius-libfreeradius-kafka = %{version}-%{release}
BuildRequires: librdkafka-devel

%description kafka
Provides a producer module to push messages into a Kafka queue

%files kafka
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_kafka.so
