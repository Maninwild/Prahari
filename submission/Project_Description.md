# Prahari

**Tagline:** Explainable web threat analysis with application-level protection.

## Problem

Small web application teams accept user-submitted links, comments and requests but often investigate suspicious inputs through disconnected tools. A prediction alone does not explain why an input was flagged or prove that an application actually stopped it.

## Solution

Prahari brings phishing URL detection, SQL injection, XSS, command injection and path traversal analysis into one product. A shared API combines machine-learning signals with explicit patterns, produces an understandable risk index and Allow/Review/Block decision, and preserves a redacted investigation record.

The included community board integrates that same API before publishing content. Allowed requests reach the handler. Blocked and held requests do not. Authenticated acknowledgements show actual integration outcomes separately from scanner recommendations.

## AI technologies

The phishing model uses a Random Forest over 18 URL features with sigmoid calibration. Its training and evaluation domains are separated, and generated benign URL variants are tracked explicitly. Request analysis uses character TF-IDF and Logistic Regression. Rules provide localized evidence and preserve multiple threat categories. Machine learning alone does not authorize blocking in this release.

## What we built

A working scan workspace, persisted history, analyst review labels, policy controls, JSON exports, authenticated acknowledgements, a durable Node event outbox, and a reusable integration client. The frontend and both model families use one architecture; the old projects are not exposed as separate apps or tabs.

## Validation

The phishing v2 model achieved 98.625% accuracy on an 8,000-row original-data test sample with separate domains. This is single-source evaluation, not a guaranteed real-world detection rate. On 26 authored request diagnostics, all 16 attack examples were held or blocked; Protect also blocked two benign examples containing code or relative paths. Eighteen backend tests, a Node outbox test, live service checks and Chromium UI checks support the implementation.

## Value and next steps

Prahari connects detection, explanation, investigation and a visible application outcome. A developer can run it locally and inspect the same decisions their application uses. Next steps are independent traffic evaluation, route-specific policy tuning and multi-user deployment controls.

## Team and links

Original projects were built by Manjunath Padgetwar and his collaborator. Enter the collaborator's name and team details in the submission form. Add the actual public GitHub repository and video URLs after publishing; they have not been created or submitted by this package.
