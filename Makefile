project = p2p

all:
	cd client/p2p && \
	cabal build p2p
	cp `cd client/p2p && cabal list-bin p2p` ./peer1
	cp `cd client/p2p && cabal list-bin p2p` ./peer2

lisp:
	cd client/p2p-test && \
	ros run -S . -l ./$(project).asd \
	-e '(ql:quickload :$(project))' \
	-e '(asdf:make :$(project))'
	cp client/p2p-test/p2p ./peer1/
	cp client/p2p-test/p2p ./peer2/

clean:
	rm -f ./peer1/p2p ./peer2/p2p client/p2p-test/p2p
