(defpackage p2p/tests/main
  (:use :cl
        :p2p
        :rove))
(in-package :p2p/tests/main)

;; NOTE: To run this test file, execute `(asdf:test-system :p2p)' in your Lisp.

(deftest test-target-1
  (testing "should (= 1 1) to be true"
    (ok (= 1 1))))
