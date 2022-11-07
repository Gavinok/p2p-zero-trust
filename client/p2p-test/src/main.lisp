(defpackage p2p
  (:use :cl))
(in-package :p2p)
(defvar *IP* "")

(defun listener ()
  (defparameter *socket* (usocket:socket-listen "localhost" 9000))
  (defparameter *connection* (usocket:socket-accept *socket* :element-type 'character))
  (unwind-protect
       (loop
         :with *socket-stream* := (usocket:socket-stream *connection*)
         :while (listen *socket-stream*)
         :do (progn (write-char (read-char *socket-stream*))
                    (force-output)))

    ;; Make sure that the sockets get's closed no matter what
    (progn (usocket:socket-close *connection*)
           (usocket:socket-close *socket*))))

(defun sender ()
  (defparameter *socket* (usocket:socket-connect "10.9.0.6" 9000))
  (unwind-protect
       (progn
         (defparameter *socket-stream* (usocket:socket-stream *socket*))
         (defun write-and-flush (message)
           (when (open-stream-p *socket-stream*)
             (write-string message *socket-stream*)
             (force-output *socket-stream*)))
         (loop
           (write-and-flush (format nil "hello~%"))
           (sleep 3)))

    ;; Make sure that the socket get's closed no matter what
    (usocket:socket-close *socket*)))

(defun main- (ip &optional port) (check-type ip string "IP addresse")
  (let ((p (or port 9040))
        (chan (make-instance 'chanl:channel)))
    ;; Start the server on a different thread
    (setf *server* (bt:make-thread (lambda () (create-client ip p chan))))
    (setf *printer* (bt:make-thread (lambda () (printer chan))))
    (create-server ip p chan)))
;; blah blah blah.
