(defpackage #:cl-rfc8252/tests
  (:use #:cl)
  (:export #:run-tests))
(in-package #:cl-rfc8252/tests)

(defvar *checks* 0 "Number of assertions in this run.")

(defun check (value)
  "Record one behavioral assertion."
  (incf *checks*)
  (unless value (error "OAuth assertion ~D failed." *checks*)))

(defun client (&rest arguments)
  "Construct a synthetic installed-app client."
  (apply #'make-instance 'cl-rfc8252:browser-authentication-client
         :authorization-endpoint "https://issuer.example/authorize"
         :token-endpoint "https://issuer.example/token" :client-id "test-app"
         arguments))

(defun failure (thunk)
  "Return a browser authentication condition signaled by THUNK."
  (handler-case (progn (funcall thunk) (error "Expected an OAuth failure."))
    (cl-rfc8252:browser-authentication-error (condition) condition)))

(defun test-pkce-and-configuration ()
  "Verify S256 generation, fresh states, and invalid loopback policy."
  (dolist (size '(32 64 96))
    (multiple-value-bind (verifier challenge)
        (cl-rfc8252:browser-authentication-create-pkce :verifier-octets size)
      (check (<= 43 (length verifier) 128))
      (check (every (lambda (character) (find character "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")) verifier))
      (check (string= challenge
                      (string-right-trim ".="
                        (cl-base64:usb8-array-to-base64-string
                         (ironclad:digest-sequence ':sha256
                          (babel:string-to-octets verifier :encoding ':ascii))
                         :uri t))))))
  (check (not (string= (cl-rfc8252:browser-authentication-state)
                      (cl-rfc8252:browser-authentication-state))))
  (dolist (arguments '((:verifier-octets 31) (:verifier-octets 97) (:ports nil)
                       (:ports (-1)) (:redirect-host "0.0.0.0") (:callback-path "relative")
                       (:callback-path "/callback?x") (:request-timeout 0) (:timeout -1)
                       (:line-limit 1) (:authorization-parameters (("state" . "override")))
                       (:token-parameters (("code_verifier" . "override")))))
    (check (eq ':configuration
               (cl-rfc8252:browser-authentication-error-stage
                (failure (lambda () (apply #'client arguments)))))))
  (let* ((client (client :scope "openid offline_access"
                         :authorization-parameters '(("prompt" . "consent"))))
         (url (cl-rfc8252:browser-authentication-authorization-url
               client :redirect-uri "http://127.0.0.1:43210/callback"
               :state "expected" :code-challenge "challenge"))
         (parameters (quri:url-decode-params (quri:uri-query (quri:uri url)))))
    (dolist (pair '(("response_type" . "code") ("state" . "expected")
                    ("code_challenge_method" . "S256") ("prompt" . "consent")
                    ("redirect_uri" . "http://127.0.0.1:43210/callback")))
      (check (equal (cdr pair) (cdr (assoc (car pair) parameters :test #'string=)))))))

(defun test-exchange-and-errors ()
  "Verify form parameters and safe metadata from successful and failed tokens."
  (let ((scoped nil) (bounded nil))
    (let ((client
            (client
             :token-parameters '(("client_secret" . "synthetic-client-secret"))
             :secret-function (lambda (thunk)
                                (setf scoped t)
                                (unwind-protect (funcall thunk) (setf scoped nil)))
             :request-function
             (lambda (&key url content)
               (check scoped)
               (check (string= url "https://issuer.example/token"))
               (dolist (pair '(("code" . "synthetic-code") ("code_verifier" . "synthetic-verifier")
                               ("client_secret" . "synthetic-client-secret")
                               ("grant_type" . "authorization_code") ("client_id" . "test-app")
                               ("redirect_uri" . "http://127.0.0.1:12/callback")))
                 (check (equal (cdr pair) (cdr (assoc (car pair) (quri:url-decode-params content) :test #'string=)))))
               (values "{\"access_token\":\"synthetic-access\"}" 200 nil)))))
      (check (string= "synthetic-access"
                      (cl-rfc8628:json-get
                       (cl-rfc8252:browser-authentication-exchange-code
                        client :code "synthetic-code" :verifier "synthetic-verifier"
                        :redirect-uri "http://127.0.0.1:12/callback") "access_token"))))
    (dolist (nested-p '(nil t))
      (let* ((secret (make-string 300 :initial-element #\z))
             (client (client
                      :bounded-string-function
                      (lambda (text &key limit)
                        (setf bounded t)
                        (check (not (search secret text)))
                        (subseq text 0 (min limit (length text))))
                      :request-function
                      (lambda (&key url content)
                        (declare (ignore url content))
                        (values
                         (cl-rfc8628:json-encode
                          (if nested-p
                              (cl-rfc8628:json-object
                               "error" (cl-rfc8628:json-object "code" secret "message" secret)
                               "access_token" secret)
                              (cl-rfc8628:json-object "error" secret "error_description" secret
                                                     "access_token" secret)))
                         400 nil))))
             (condition (failure
                         (lambda ()
                           (cl-rfc8252:browser-authentication-exchange-code
                            client :code secret :verifier "synthetic-verifier" :redirect-uri "redirect")))))
        (check bounded)
        (check (= 400 (cl-rfc8252:browser-authentication-error-status condition)))
        (check (not (search (subseq secret 0 256) (or (cl-rfc8252:browser-authentication-error-code condition) ""))))
        (check (stringp (cl-rfc8252:browser-authentication-error-response condition)))
        (check (not (search secret (princ-to-string condition)))))))
  (dolist (body '("[]" "false" "{" "{\"error\":\"invalid_grant\"}"))
    (check (eq ':token
               (cl-rfc8252:browser-authentication-error-stage
                (failure (lambda ()
                           (cl-rfc8252:browser-authentication-token-document
                            (client :request-function (lambda (&key url content)
                                                        (declare (ignore url content))
                                                        (values body 200 nil)))))))))))

(define-condition test-host-error (error) ())

(defun test-request-policy ()
  "Apply host deadlines to injected transports and propagate safe host errors."
  (let ((wrapped nil) (host-error (make-condition 'test-host-error)))
    (handler-case
        (cl-rfc8252:browser-authentication-token-document
         (client :error-type 'test-host-error
                 :request-wrapper (lambda (thunk) (setf wrapped t) (funcall thunk))
                 :request-function (lambda (&key url content)
                                     (declare (ignore url content))
                                     (check wrapped)
                                     (error host-error))))
      (test-host-error (caught) (check (eq caught host-error))))
    (check wrapped)))

(defun send-request (port line &key (terminate t))
  "Send one local request, optionally without CRLF, and return response octets."
  (let ((socket (usocket:socket-connect "127.0.0.1" port :element-type '(unsigned-byte 8))))
    (unwind-protect
         (let ((stream (usocket:socket-stream socket)))
           (write-sequence (if (stringp line) (babel:string-to-octets line :encoding ':utf-8) line) stream)
           (when terminate (write-sequence #(13 10) stream))
           (finish-output stream)
           (let ((bytes (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
             (handler-case
                 (loop for byte = (read-byte stream nil nil) while byte do (vector-push-extend byte bytes))
               (stream-error () nil))
             bytes))
      (cl-rfc8252:browser-authentication-loopback-close socket))))

(defun run-loopback (client requests &key (timeout 3) (state "expected"))
  "Run requests on a thread and return callback result, responses, and elapsed time."
  (multiple-value-bind (listener redirect-uri) (cl-rfc8252:browser-authentication-loopback-open client)
    (declare (ignore redirect-uri))
    (let* ((port (usocket:get-local-port listener))
           (responses nil) (thread-error nil)
           (thread (bordeaux-threads:make-thread
                    (lambda ()
                      (handler-case
                          (dolist (request requests)
                            (push (apply #'send-request port request) responses))
                        (error (condition) (setf thread-error condition))))))
           (started (get-internal-real-time)))
      (unwind-protect
           (let ((result (handler-case
                             (cl-rfc8252:browser-authentication-await-loopback client listener state :timeout timeout)
                           (cl-rfc8252:browser-authentication-error (condition) condition))))
             (bordeaux-threads:join-thread thread)
             (when thread-error (error thread-error))
             (values result (nreverse responses)
                     (/ (- (get-internal-real-time) started) internal-time-units-per-second)))
        (cl-rfc8252:browser-authentication-loopback-close listener)
        (when (bordeaux-threads:thread-alive-p thread) (bordeaux-threads:destroy-thread thread))))))

(defun test-loopback ()
  "Verify multiple connections, strict state/path parsing, and bounded readers."
  (multiple-value-bind (code responses elapsed)
      (run-loopback
       (client :request-timeout 0.15 :line-limit 128)
       (list '("GET /favicon.ico HTTP/1.1")
             '("GET /callback?state=wrong&code=unrelated HTTP/1.1")
             '("GET /callback?state=expected&state=wrong&code=ambiguous HTTP/1.1")
             '("GET /callback?state=expected&code=bad%XX HTTP/1.1")
             '("GET /callback?state=expected&error=denied%XX HTTP/1.1")
             '("GET /callback?state=wrong&error=access_denied HTTP/1.1")
             '("POST /callback?state=expected&code=wrong-method HTTP/1.1")
             '("GET /callback?state=expected&code=fragment#x HTTP/1.1")
             '("GET /callback?state=expected&code=partial" :terminate nil)
             (list (make-string 200 :initial-element #\x) :terminate nil)
             (list (vector 71 69 84 32 195) :terminate nil)
             '("GET /callback?state=expected&code=valid%2Bcode HTTP/1.1")))
    (check (string= code "valid+code"))
    (check (= 12 (length responses)))
    (check (< elapsed 3)))
  (multiple-value-bind (result responses elapsed)
      (run-loopback (client :request-timeout 5)
                    '(("GET /callback?state=expected&code=unfinished" :terminate nil)) :timeout 0.2)
    (declare (ignore responses))
    (check (typep result 'cl-rfc8252:browser-authentication-error))
    (check (<= 0.15 elapsed 1.5)))
  (multiple-value-bind (result responses elapsed)
      (run-loopback (client) '(("GET /callback?state=expected&error=access_denied&error_description=expected HTTP/1.1")))
    (declare (ignore responses elapsed))
    (check (string= (cl-rfc8252:browser-authentication-error-code result) "access_denied"))
    (check (not (search "expected" (cl-rfc8252:browser-authentication-error-response result)))))
  (multiple-value-bind (code responses elapsed)
      (run-loopback (client :success-response "Přihlášení dokončeno."
                            :state-test (lambda (received expected)
                                          (or (string= received expected)
                                              (string= received (concatenate 'string expected ".variant")))))
                    '(("GET /callback?state=expected.variant&code=variant HTTP/1.1")))
    (declare (ignore elapsed))
    (check (string= code "variant"))
    (let* ((bytes (first responses))
           (text (babel:octets-to-string bytes :encoding ':utf-8))
           (separator (search (format nil "~C~C~C~C" #\Return #\Newline #\Return #\Newline) text))
           (length-start (+ (search "Content-Length: " text) (length "Content-Length: "))))
      (check (= (parse-integer text :start length-start :junk-allowed t)
                (length (babel:string-to-octets (subseq text (+ separator 4)) :encoding ':utf-8))))))
  (let ((occupied (usocket:socket-listen "127.0.0.1" 0 :element-type '(unsigned-byte 8))))
    (unwind-protect
         (multiple-value-bind (listener redirect)
             (cl-rfc8252:browser-authentication-loopback-open
              (client :ports (list (usocket:get-local-port occupied) 0) :redirect-host "localhost"))
           (unwind-protect
                (progn (check (search "http://localhost:" redirect))
                       (check (/= (usocket:get-local-port listener) (usocket:get-local-port occupied))))
             (cl-rfc8252:browser-authentication-loopback-close listener)))
      (cl-rfc8252:browser-authentication-loopback-close occupied))))

(defclass test-source (cl-rfc8628:credential-source)
  ((saved :initform nil :accessor saved)))
(defmethod cl-rfc8628:credential-source-save ((source test-source) credentials)
  (setf (saved source) credentials))
(defclass test-manager (cl-rfc8628:managed-credential-manager) ())
(defmethod cl-rfc8628:credential-manager-provider-label ((manager test-manager))
  (declare (ignore manager))
  "Test OAuth")

(defun test-login-publication ()
  "Verify credential publication, secret scope, and listener cleanup on failures."
  (dolist (fail-stage '(nil :callback :transport :credentials :browser))
    (let* ((source (make-instance 'test-source))
           (manager (make-instance 'test-manager :primary-source source))
           (port nil) (region-depth 0)
           (credentials (make-instance 'cl-rfc8628:oauth-credentials :access-token "synthetic-access"
                                        :refresh-token "synthetic-refresh" :account-id "synthetic-account"))
           (client (client
                    :secret-function (lambda (thunk)
                                       (incf region-depth)
                                       (unwind-protect (funcall thunk) (decf region-depth)))
                    :request-function (lambda (&key url content)
                                        (declare (ignore url content))
                                        (check (plusp region-depth))
                                        (when (eq fail-stage ':transport) (error "Synthetic transport failure."))
                                        (values "{\"access_token\":\"synthetic-access\"}" 200 nil))
                    :credential-function (lambda (manager document)
                                           (declare (ignore manager document))
                                           (check (plusp region-depth))
                                           (when (eq fail-stage ':credentials) (error "Synthetic validation failure."))
                                           credentials)
                    :display-function (lambda (url &key redirect-uri timeout stream)
                                        (declare (ignore url timeout stream))
                                        (setf port (quri:uri-port (quri:uri redirect-uri)))))))
      (handler-case
          (let ((result (cl-rfc8252:browser-authentication-login
                         client manager :stream (make-broadcast-stream)
                         :browser-function (lambda (url)
                                             (declare (ignore url))
                                             (when (eq fail-stage ':browser) (error "Synthetic browser failure.")) t)
                         :callback-function (lambda (listener state &key timeout)
                                              (declare (ignore listener state timeout))
                                              (check (plusp region-depth))
                                              (when (eq fail-stage ':callback) (error "Synthetic callback failure."))
                                              "synthetic-code"))))
            (check (eq result credentials)))
        (error (condition)
          (unless fail-stage (error condition))))
      (check (zerop region-depth))
      (check (eq (not (null (saved source))) (not (null (member fail-stage '(nil :browser))))))
      (when port
        (let ((replacement (usocket:socket-listen "127.0.0.1" port :element-type '(unsigned-byte 8))))
          (check replacement)
          (cl-rfc8252:browser-authentication-loopback-close replacement))))))

(defun run-tests ()
  "Run all offline protocol and real-loopback checks."
  (let ((*checks* 0))
    (test-pkce-and-configuration)
    (test-exchange-and-errors)
    (test-request-policy)
    (test-loopback)
    (test-login-publication)
    (format t "~&cl-rfc8252: ~D checks passed.~%" *checks*)
    t))
