(defpackage p2p
  (:use :cl))
(in-package :p2p)

(defun ip-p (ip)
  "If IP is not a valid IP address return nil"
  (or (string= ip "localhost")
      (find #\. ip)))

;; Type definition for what is and is not an IP address
(deftype Ip ()
  `(satisfies ip-p))

(defvar *IP* "localhost")
(defvar *PORT* 9000)

(defun write-and-flush (message stream)
  "Write MESSAGE to STREAM and force the output rather than buffering."
  (when (open-stream-p stream)
    (write-string message stream)
    (force-output stream)))

(defun tcp-request-handler (stream)
  "Function called when processing input from a TCP socket."
  (loop
    :while (listen stream)
    :do (progn (write-char (read-char stream))
               (force-output))))

(defun listener (ip port &optional (in-new-thread nil))
  "Server started for handling incoming TCP requests from IP on PORT"
  (defparameter *listener-thread*
    (usocket:socket-server ip port
                           #'tcp-request-handler nil
                           :element-type 'character
                           :in-new-thread in-new-thread)))

(defun sender (ip port)
  "Client who will send a TCP packet to the server at IP listing on PORT every 10 seconds
PREREQUISIT: Server must be running before client is started"
  (loop :repeat 10000
        :do (progn
              (usocket:with-client-socket (s stream ip port
                                             :element-type 'character)
                (write-and-flush
                 (format nil "hello~%") stream)
                (sleep 3)))))

(defun client (ip &optional (port *port*))
  "Basic client for protocol which will send TCP packets to IP on PORT"
  (sender ip port))

(defun server (ip &optional (port *port*))
  "Basic server that will handle TCP requests on IP on PORT"
  (listener ip port))

(defun maybe-help (args)
  (when (member "-h" args
                :test #'string=)
    (format t "command {ip-address} [-p port-number]
command -h

   -h prints this help message
   -p sets the current port number (defaults to 9000)")
    (uiop:quit)))

(defun main- ()
  "Function ran at executable startup"

  ;; Print help message if the -h cli argument was passed to the
  ;; program
  (maybe-help (uiop:command-line-arguments))

  (let* ((args     (uiop:command-line-arguments))
         (endpoint (first args))
         (ip       (second args))
         (port     (when (member "-p" args :test #'string=)
                     (parse-integer (car (last args))))))

    (check-type ip Ip "IP address")
    (check-type port Integer "Port must be an integer")

    (format t "~a ~a ~a~%" endpoint ip port)

    (cond
      ((string= endpoint "client") (client ip port))
      ((string= endpoint "server") (server ip port))
      (t (error "Endpoint must be either 'client' or 'server' ~a is invalid" endpoint)))))
