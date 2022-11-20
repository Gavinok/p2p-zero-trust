(defsystem "p2p"
  :version "0.1.0"
  :author ""
  :license ""
  :depends-on (usocket
               usocket-server
               chanl)
  :components ((:module "src"
                :components
                ((:file "main"))))
  :description ""
  :in-order-to ((test-op (test-op "p2p/tests")))
  :build-operation "program-op"
  :entry-point "p2p::main-")
