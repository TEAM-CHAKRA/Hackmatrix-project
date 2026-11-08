# Distrusted Certificate Authorities - Pending User Verification

## eMudhra CA
- **Status:** EXCLUDED from `src/data/distrustedCAs.json` pending verification of final primary-source policy notices.
- **Context:**
  Discussions arose in the Google Chrome Root Program and Mozilla Bugzilla regarding compliance issues, incident response delays, and potential distrust timelines for eMudhra roots.
- **Reason for Exclusion:**
  Per project instruction (*"If eMudhra can't be verified, leave it out and list it in a TODO file for me"*), only CAs with cited and verified official public release dates and primary-source URLs are included in `distrustedCAs.json`.
- **Action for User:**
  Review whether to distrust specific eMudhra root fingerprints (and effective distrust dates) once official root-store policy announcements (e.g. Mozilla CA certificate module release or Google Chrome Root Program deprecation bulletin) are published.

