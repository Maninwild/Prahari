# Demo narration — under five minutes

The included MP4 is a captioned recording of the running product. It has no voice narration. Use it directly where captioned video is accepted, or record this narration over a fresh demonstration.

**Opening:** We built Prahari for small web application teams that need to inspect suspicious links and requests. It combines five threat categories in one shared analysis and protection workflow.

**Workspace:** Here we submit an ordinary request. Prahari returns Allow, with a risk breakdown and detector coverage. Now we submit script markup. The Protect policy returns Block and shows the matched pattern. Model estimates and rule evidence are separate, so the user can see what caused the decision.

**Investigation:** The result is saved without retaining the original input. We can reopen it, export the analysis and record an analyst verdict. Review labels do not silently retrain the system or override future requests.

**Application:** This community board uses Prahari's API before its publishing handler. The benign submission returns HTTP 200 and appears on the board. The handler count increases. Script markup returns HTTP 403, while the handler count stays unchanged. A suspicious link returns HTTP 409 for review and is not published.

**Evidence of enforcement:** The dashboard counts actual adapter acknowledgements separately from Block recommendations. Events are authenticated, duplicate-safe and retried from a persistent outbox. Scanner outages deny requests without labelling the outage an attack.

**AI and evaluation:** The phishing model uses corrected URL features, a Random Forest and calibration. Domains are separated across training and evaluation. The request model uses character TF-IDF and Logistic Regression, with explicit rules for recognizable attack patterns. The phishing test accuracy is 98.625% on 8,000 rows from one source. This does not guarantee real-world accuracy. The authored request diagnostics also exposed benign code false positives, which is why review-first and monitor workflows matter.

**Close:** Prahari is a working local product with a reusable integration, documented setup, a public-repository-ready source package and reproducible checks. Our next step is broader independent evaluation and application-specific policy tuning.
