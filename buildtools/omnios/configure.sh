autoreconf -i

./configure \
  --prefix=/opt/circonus/ \
  --exec-prefix=/opt/circonus \
  --sysconfdir=/opt/circonus/etc \
  --includedir=/opt/circonus/include \
  --bindir=/opt/circonus/bin \
  --sbindir=/opt/circonus/sbin \
  --libdir=/opt/circonus/lib/amd64/ \
  --libexecdir=/opt/circonus/libexec/amd64/
