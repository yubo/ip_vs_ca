RPMBUILD=~/rpmbuild/

all: srpm kmod

srpm:
	mkdir -p $(RPMBUILD)/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	tar -cjf $(RPMBUILD)/SOURCES/ip_vs_ca.tar.bz2 -C src ip_vs_ca
	cp src/ip_vs_ca-kmodtool.sh $(RPMBUILD)/SOURCES
	cp src/ip_vs_ca-kmod.spec $(RPMBUILD)/SPECS
	rpmbuild -bs $(RPMBUILD)/SPECS/ip_vs_ca-kmod.spec

kmod:
	rpmbuild --rebuild $(RPMBUILD)/SRPMS/ip_vs_ca*.rpm

clean:
	rm -rf out/*
