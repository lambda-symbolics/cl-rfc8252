(asdf:defsystem #:cl-rfc8252
  :description "Installed-app browser OAuth with S256 PKCE and loopback redirects."
  :author "Lambda Symbolics OÜ"
  :license "COLL-Attribution"
  :version "0.1.0"
  :serial t
  :depends-on (#:cl-rfc8628 #:ironclad #:usocket #:cl-base64 #:babel #:quri)
  :components ((:module "src"
                :serial t
                :components ((:file "package")
                             (:file "client")
                             (:file "loopback")
                             (:file "flow"))))
  :in-order-to ((asdf:test-op (asdf:test-op #:cl-rfc8252/tests))))

(asdf:defsystem #:cl-rfc8252/tests
  :description "Offline protocol and loopback tests for cl-rfc8252."
  :depends-on (#:cl-rfc8252 #:bordeaux-threads)
  :serial t
  :components ((:module "tests" :components ((:file "tests"))))
  :perform (asdf:test-op (operation component)
             (declare (ignore operation component))
             (uiop:symbol-call '#:cl-rfc8252/tests '#:run-tests)))
