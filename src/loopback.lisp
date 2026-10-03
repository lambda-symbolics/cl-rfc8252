(in-package #:cl-rfc8252)

;;;; -- IPv4 Loopback Listener --

(defun browser-authentication-loopback-open (client)
  "Bind IPv4 loopback and return the listener and advertised redirect URI.
Try CLIENT's registered ports in order; zero requests an ephemeral port."
  (dolist (port (client-ports client))
    (let ((listener
            (handler-case
                (usocket:socket-listen "127.0.0.1" port
                                       :reuse-address t
                                       :element-type '(unsigned-byte 8))
              (usocket:socket-error () nil))))
      (when listener
        (return-from browser-authentication-loopback-open
          (values listener
                  (format nil "http://~A:~D~A"
                          (client-redirect-host client)
                          (usocket:get-local-port listener)
                          (client-callback-path client)))))))
  (browser-authentication--fail client ':listener
                                "Could not bind an OAuth loopback callback port."))

(defun browser-authentication-loopback-close (listener)
  "Close LISTENER or an accepted socket, tolerating an already closed socket."
  (when listener
    (ignore-errors (usocket:socket-close listener)))
  (values))

(defun browser-authentication--remaining (client deadline)
  "Return nonnegative seconds until the absolute monotonic DEADLINE."
  (max 0 (- deadline (funcall (client-clock-function client)))))

(defun browser-authentication--read-line (client connection deadline)
  "Read one bounded ASCII request line without blocking on partial characters.
Return NIL on timeout, EOF, excessive length, or malformed line framing."
  (let ((stream (usocket:socket-stream connection))
        (octets (make-array (client-line-limit client)
                            :element-type '(unsigned-byte 8)))
        (index 0))
    (handler-case
        (loop while (< index (length octets))
              for remaining = (browser-authentication--remaining client deadline)
              do (when (zerop remaining) (return nil))
                 ;; LISTEN accounts for bytes already buffered in the Lisp stream.
                 (when (or (listen stream)
                           (usocket:wait-for-input connection :timeout remaining :ready-only t))
                   (let ((byte (read-byte stream nil nil)))
                     (unless byte (return nil))
                     (setf (aref octets index) byte)
                     (when (= byte 10)
                       (return
                         (and (plusp index) (= (aref octets (1- index)) 13)
                              (every (lambda (value) (<= 32 value 126))
                                     (subseq octets 0 (1- index)))
                              (map 'string #'code-char (subseq octets 0 (1- index))))))
                     (incf index)))
              finally (return nil))
      (stream-error () nil)
      (usocket:socket-error () nil))))

(defun browser-authentication--query (text)
  "Decode a callback query strictly, rejecting repeated keys and bad escapes."
  (handler-case
      (let ((parameters nil))
        (dolist (part (uiop:split-string text :separator '(#\&)))
          (loop for index from 0 below (length part)
                when (char= (char part index) #\%)
                  do (unless (and (< (+ index 2) (length part))
                                  (digit-char-p (char part (1+ index)) 16)
                                  (digit-char-p (char part (+ index 2)) 16))
                       (return-from browser-authentication--query nil))
                     (incf index 2))
          (let* ((separator (position #\= part))
                 (key (quri:url-decode (subseq part 0 separator)))
                 (value (if separator (quri:url-decode (subseq part (1+ separator))) "")))
            (when (assoc key parameters :test #'string=)
              (return-from browser-authentication--query nil))
            (push (cons key value) parameters)))
        parameters)
    (error () nil)))

(defun browser-authentication--request-parameters (client line)
  "Return query parameters only for an exact GET callback path."
  (when line
    (let ((fields (uiop:split-string line :separator '(#\Space))))
      (when (and (= (length fields) 3)
                 (string= (first fields) "GET")
                 (member (third fields) '("HTTP/1.0" "HTTP/1.1") :test #'string=))
        (let* ((target (second fields))
               (separator (position #\? target)))
          (when (and separator
                     (not (position #\# target))
                     (string= (subseq target 0 separator) (client-callback-path client)))
            (browser-authentication--query (subseq target (1+ separator)))))))))

(defun browser-authentication--respond (connection status body)
  "Send a small non-secret UTF-8 text response with an octet Content-Length."
  (let* ((body-octets (babel:string-to-octets body :encoding ':utf-8))
         (header (format nil "HTTP/1.1 ~A~C~CContent-Type: text/plain; charset=utf-8~C~CContent-Length: ~D~C~CConnection: close~C~C~C~C"
                         status #\Return #\Newline #\Return #\Newline
                         (length body-octets) #\Return #\Newline
                         #\Return #\Newline #\Return #\Newline)))
    (handler-case
        (let ((stream (usocket:socket-stream connection)))
          (write-sequence (babel:string-to-octets header :encoding ':ascii) stream)
          (write-sequence body-octets stream)
          (finish-output stream))
      (stream-error () nil)
      (usocket:socket-error () nil))))

(defun browser-authentication-await-loopback (client listener state &key (timeout (client-timeout client)))
  "Wait for a matching state and authorization code within TIMEOUT seconds.
Ignore malformed, unrelated, and mismatched requests. Bound each connection's
request reading separately, always close it, and validate state before errors."
  (browser-authentication--validate-timeout client timeout)
  (let ((deadline (+ (funcall (client-clock-function client)) timeout)))
    (loop
      (let ((remaining (browser-authentication--remaining client deadline)))
        (when (zerop remaining)
          (browser-authentication--fail client ':callback
                                        "Timed out waiting for the OAuth browser callback."))
        (when (usocket:wait-for-input listener :timeout remaining :ready-only t)
          (let ((connection (usocket:socket-accept listener :element-type '(unsigned-byte 8))))
            (unwind-protect
                 (let* ((request-deadline
                          (min deadline (+ (funcall (client-clock-function client))
                                           (client-request-timeout client))))
                        (line (browser-authentication--read-line client connection request-deadline))
                        (parameters (browser-authentication--request-parameters client line))
                        (received-state (cdr (assoc "state" parameters :test #'string=)))
                        (code (cdr (assoc "code" parameters :test #'string=)))
                        (oauth-error (cdr (assoc "error" parameters :test #'string=))))
                   (cond
                     ((not parameters)
                      (browser-authentication--respond connection "404 Not Found" "Not an OAuth callback."))
                     ((not (and (non-empty-string-p received-state)
                                (funcall (client-state-test client) received-state state)))
                      (browser-authentication--respond connection "400 Bad Request"
                                                       (client-mismatch-response client)))
                     ((non-empty-string-p oauth-error)
                      (browser-authentication--respond connection "400 Bad Request"
                                                       (client-failure-response client))
                      (let ((secrets (append (list state received-state code)
                                             (loop for (key . value) in parameters
                                                   when (member key '("access_token" "refresh_token" "id_token" "client_secret")
                                                                :test #'string=)
                                                     collect value))))
                        (browser-authentication--fail
                         client ':callback "The OAuth authorization request was rejected."
                         :code (browser-authentication-redacted-value client oauth-error secrets)
                         :response (browser-authentication-redacted-value
                                    client (cdr (assoc "error_description" parameters :test #'string=)) secrets))))
                     ((non-empty-string-p code)
                      (browser-authentication--respond connection "200 OK" (client-success-response client))
                      (return-from browser-authentication-await-loopback code))
                     (t
                      (browser-authentication--respond connection "400 Bad Request" (client-failure-response client))
                      (browser-authentication--fail client ':callback
                                                    "The OAuth callback did not contain an authorization code."))))
              (browser-authentication-loopback-close connection))))))))
