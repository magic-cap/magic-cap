;; this extracts the Org-mode examples from the README.org into a .sh
;; file. Thanks to chmod222 in Libera #emacs for pointing out
;; org-babel-tangle

(find-file '"README.org")
(org-babel-tangle)
