# SpamSentry-ML

**Supervised machine learning for explainable email spam detection.**

SpamSentry-ML trains a TF-IDF text representation and an L2-regularized logistic regression classifier on labeled spam and legitimate messages. The fitted model predicts spam likelihood from an email's subject and body. A FastAPI application serves it through a private dashboard with Clerk authentication, account-specific history, and downloadable reports. The interface is branded **Postmark**.

The repository includes a **trained model**, **reproducible training pipeline**, and **measured evaluation results**. Inference runs on your server without an external AI API.

## Run locally

Use Python 3.11 or 3.12 for a new installation. The training environment used Python 3.9.6; the numerical stack is pinned in `requirements-ml.txt`. The committed model is ready to use after installation; training downloads are not required for inference.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # Only for a new checkout; don't overwrite configured credentials.
# Set CLERK_PUBLISHABLE_KEY in .env before opening the workspace.
python run.py
```

Open **http://127.0.0.1:8000** for the landing page. Sign in at `/auth/login`, create an account at `/auth/register`, and use the analyzer at `/dashboard`. Interactive API documentation is at **http://127.0.0.1:8000/docs**.

No Node.js, frontend build, or external AI service is required. FastAPI serves the HTML, CSS, and JavaScript directly. A Clerk application and publishable key are required for sign-in. The interface uses Google Fonts when available, with local font fallbacks.

## Features

- Public landing page with product preview, features, process, and FAQs.
- Clerk sign-up, sign-in, account menu, and sign-out.
- Server-verified sessions and account-specific history, statistics, report access, and CSV exports.
- Email composer, character counter, keyboard shortcut (`Cmd/Ctrl + Enter`), and three built-in demo emails.
- Plain-text email file import; MIME `.eml` files use their plain-text part. HTML-only emails should be pasted as readable text.
- Likely safe, suspicious, and likely spam verdicts with a 0–100 risk score.
- Weighted signals, matched text, four category totals, word/link counts, and actual evaluation time.
- Persistent, searchable history with filtering and pagination.
- JSON report download and CSV history export.
- Responsive layout, keyboard accessible controls, and reduced-motion support.
- Model information page with measured evaluation results and 13 supplemental security checks.

## Database: local SQLite or Neon

SQLite works out of the box. Its file is created at `data/postmark.db` on startup. History starts empty; sample messages are analyzed only when you submit them.

To use your Neon database:

1. Copy `.env.example` to `.env`.
2. Set `DATABASE_URL` to the connection string from your Neon dashboard. Keep `sslmode=require`.
3. Restart the app. The `analyses` table is created automatically if it does not exist.

```dotenv
DATABASE_URL=postgresql://USER:PASSWORD@YOUR-HOST.neon.tech/neondb?sslmode=require
HOST=127.0.0.1
PORT=8000
```

Credentials belong in the git-ignored `.env` file and are not included in source control. Existing SQLite records are not automatically copied when changing to Neon. All email text and findings are stored in whichever database you configure. `DATABASE_URL` uses the pooled connection for the app; `DATABASE_DIRECT_URL` can be kept for external migration tools and is not needed at runtime.

## Clerk authentication

Configure these environment variables:

```dotenv
CLERK_PUBLISHABLE_KEY=pk_test_YOUR_PUBLISHABLE_KEY
CLERK_AUTHORIZED_PARTIES=http://127.0.0.1:8000,http://localhost:8000
# Optional, for future Clerk Backend API user-management calls:
# CLERK_SECRET_KEY=sk_test_YOUR_SECRET_KEY
```

`NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` is accepted as an alias. The routes are `/auth/login`, `/auth/register`, and `/dashboard`, matching the Clerk settings. `/sign-in` and `/sign-up` redirect to the corresponding auth routes. Nested Clerk verification routes are supported. Add your deployed app's exact origin to `CLERK_AUTHORIZED_PARTIES` before hosting; use HTTPS for production.

The frontend loads ClerkJS and Clerk UI from your Clerk instance. Passwords, social login, verification, and account management use Clerk's components and follow the settings enabled in your Clerk dashboard. On successful authentication, the user is sent to `/dashboard`.

Every private API request sends a short-lived Clerk session token in the `Authorization: Bearer ...` header. Python verifies its RS256 signature against the instance's cached public keys and validates the issuer, expiry, not-before time, issued-at time, authorized origin, user ID, session ID, and active session status. The secret key is never delivered to the browser and is not required for public-key session verification. Tokens are not saved to local storage by the app. There is no unauthenticated demo bypass.

Analyses are assigned to the verified user ID on the server. A user cannot supply another owner ID to access someone else's records. Unowned analyses created before authentication was added remain unassigned and hidden; the startup migration adds ownership without deleting or exposing old records.

The dashboard's HTML is a public, data-free shell, hidden until a session is verified. Its email data, uploads, detection rules, statistics, and exports require authentication. Public endpoints are the landing/auth pages, `/api/auth/config` (publishable key only), and `/api/health`. User-specific API responses have `Cache-Control: no-store`.

## Model and algorithms

1. **Preprocessing:** parse MIME emails, prefer plain text with an HTML fallback during training, strip HTML markup, decode entities, normalize whitespace, and lowercase subject/body text. Sender addresses and transport headers are excluded from the text model.
2. **TF-IDF:** learn up to 60,000 word unigrams and bigrams from the training split. Use sublinear term frequency, smoothed inverse document frequency, and L2 normalization (`min_df=2`, `max_df=0.98`). The vocabulary is learned from data.
3. **Logistic regression:** learn coefficients by minimizing regularized classification loss. Configuration: L2 penalty, `C=4`, balanced class weights, `liblinear`, up to 1,000 iterations. Prediction: `P(spam | text) = sigmoid(w · x + b)`.
4. **Explanation:** display the strongest present terms by the magnitude of `TF-IDF × learned coefficient`. Positive log-odds contributions favor spam; negative ones favor legitimate text. The displayed subset does not include every term or the intercept.
5. **Security policy:** combine the trained prediction with supplemental checks for credential requests, suspicious links, sender mismatches, and formatting. These checks use separate policy weights rather than learned model coefficients.

See scikit-learn's official explanations of [text features](https://scikit-learn.org/stable/modules/feature_extraction.html#text-feature-extraction) and [logistic regression](https://scikit-learn.org/stable/modules/linear_model.html#logistic-regression).

```mermaid
flowchart LR
    A[Labeled messages] --> B[Normalize and deduplicate]
    B --> C[Train / validation / test split]
    C --> D[Fit TF-IDF and logistic regression on training only]
    D --> E[Evaluate and save model]
    E --> F[Predict new email]
    F --> G[Model estimate + security policy]
    G --> H[Verdict, evidence, and saved report]
```

## Datasets and training

- **[Apache SpamAssassin public mail corpus](https://spamassassin.apache.org/old/publiccorpus/):** the `20030228` easy ham, easy ham 2, hard ham, and spam archives, plus corrected `20050311` spam 2. These provide real emails. See the corpus [provenance and usage notes](https://spamassassin.apache.org/old/publiccorpus/readme.html); message copyrights remain with their original senders.
- **[UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms%2Bspam%2Bcollection):** auxiliary short-message data to support pasted snippets. Citation: Almeida, T. & Hidalgo, J. (2011), *SMS Spam Collection*, UCI, [DOI: 10.24432/C5CC84](https://doi.org/10.24432/C5CC84), CC BY 4.0. These are SMS messages, not emails; results are separated by domain below.

The pipeline parses 11,614 usable messages, skips 6 malformed or empty emails, and removes 733 duplicate or conflicting-label records. It hashes normalized bodies before splitting, keeping one copy of each body and removing conflicting-label bodies. This leaves **10,881 unique messages**. Exact normalized bodies cannot appear in multiple splits; near-duplicates and related threads may remain.

| Split | Emails | SMS | Total | Legitimate | Spam |
| --- | ---: | ---: | ---: | ---: | ---: |
| Training | 4,005 | 3,611 | 7,616 | 6,030 | 1,586 |
| Validation | 858 | 774 | 1,632 | 1,292 | 340 |
| Test | 859 | 774 | 1,633 | 1,293 | 340 |

The approximately 70/15/15 split is stratified by domain and label with seed `42`. Vocabulary, IDF statistics, and classifier coefficients are fitted on training data only. The committed artifact is the evaluated training-split model, without refitting on validation or test data.

An email-only prototype was evaluated during development. Validation experiments and short-message behavior informed the addition of SMS data. These are reproducible development holdout estimates, not an independent blind evaluation.

## Measured results

These results evaluate the **text classifier alone** at `P(spam) >= 0.5`, excluding supplemental security checks. Precision, recall, and F1 refer to spam.

| Evaluation | Messages | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Validation, combined | 1,632 | 98.10% | 95.85% | 95.00% | 95.42% |
| Test, combined | 1,633 | **98.41%** | **95.91%** | **96.47%** | **96.19%** |
| Test, email only | 859 | 98.25% | 96.36% | 97.54% | 96.95% |
| Test, SMS only | 774 | 98.58% | 94.74% | 93.75% | 94.24% |
| Complement Naive Bayes, combined test | 1,633 | 97.18% | 97.42% | 88.82% | 92.92% |

Combined test confusion matrix:

| Actual / predicted | Legitimate | Spam |
| --- | ---: | ---: |
| Legitimate | 1,279 | 14 |
| Spam | 12 | 328 |

Combined test ROC-AUC is **0.9970**. Always predicting the majority legitimate class yields **79.18% accuracy**. Complement Naive Bayes uses the same training-fitted TF-IDF features. Full results, source archive checksums, artifact checksum, library versions, and split body hashes are in [`models/training_report.json`](models/training_report.json).

## Strict detection policy

```text
model_score  = round(100 × predicted spam probability)
policy_score = min(100, sum of matched security-check weights)
final_score  = max(model_score, policy_score)
```

| Final score | Verdict |
| --- | --- |
| 0–19 | Likely safe |
| 20–49 | Suspicious; review recommended |
| 50–100 | Likely spam |

Each supplemental check contributes at most once. A sensitive-information request contributes 40 points and urgency contributes 20; together they flag a message even when the text classifier gives a low estimate. Category totals and model evidence are displayed separately and should not be added to reconstruct the final score.

The final score combines model output with policy points and is **not a calibrated probability**. Conservative thresholds can flag legitimate text for review. Historical, English-heavy datasets and random splits do not establish performance on modern phishing, multilingual messages, or a different inbox. Near-duplicate and thread overlap can inflate results. The app does not authenticate senders with SPF/DKIM/DMARC, visit URLs, inspect attachments, or verify factual claims.

Legacy saved reports retain their original engine version. Analyze an email again to obtain a result from the trained model.

## Reproduce training

With the virtual environment active, run from the repository root:

```bash
python -m ml.train
```

The script downloads archives into git-ignored `data/corpus/`, prepares fixed splits, trains the model and baseline, evaluates them, and writes:

- `models/spam_classifier.joblib`: fitted TF-IDF vectorizer and classifier.
- `models/training_report.json`: measured results and reproducibility metadata.

Raw datasets and private application data are not committed. Archive SHA-256 values, version pins, seed, and split hashes support reproduction. Byte-identical artifacts across Python versions or operating systems are not guaranteed. Only load the trusted repository artifact or one you train yourself; uploaded joblib files are never used.

## API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/api/analyze` | Analyze and save `{ "sender": "", "subject": "", "body": "..." }` |
| POST | `/api/import` | Read a multipart `.eml` or `.txt` file (100 KB limit) |
| GET | `/api/analyses` | History; `q`, `verdict`, `limit`, `offset` |
| GET | `/api/analyses/{id}` | Saved analysis |
| GET | `/api/stats` | Actual workspace counts and average evaluation time |
| GET | `/api/rules` | Supplemental security checks and thresholds |
| GET | `/api/model` | Model metadata and measured evaluation results |
| GET | `/api/export` | CSV export of history |
| GET | `/api/health` | Engine status |
| GET | `/api/auth/config` | Public Clerk frontend configuration (never secrets) |
| GET | `/api/me` | Verify the current signed-in session |

Except for health and auth configuration, API endpoints require a Clerk bearer token. In the interactive API docs, use **Authorize** with a current Clerk session token.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

Tests cover trained artifact integrity, disjoint dataset splits, learned evidence, model thresholds, security-policy overrides, email classification, input validation, imports, persistence, search, CSV safety, authentication requirements, real RSA signature verification with generated test keys, invalid claims/signatures, cross-account access isolation, and preservation of legacy records. Tests use isolated SQLite databases and never connect to or mutate the configured Neon database. Live Clerk account creation and email verification are completed by the user through Clerk.

## Project structure

```text
app/
  main.py             FastAPI routes, static frontend, imports, exports
  auth.py             Clerk session validation with public signing keys
  engine.py           Model/security aggregation and explanations
  ml.py               Shared preprocessing and trained inference
  schemas.py          Validated requests and responses
  database.py         SQLAlchemy models; SQLite / Neon connection
  static/
    landing.html      Public product landing page
    landing.css       Landing and authentication layouts
    auth.html         Clerk sign-in and sign-up screen
    auth.js           Clerk initialization, session guard, account menu
    index.html        Analysis, history, and detection-engine screens
    styles.css        Responsive interface
    app.js            API integration and UI interactions
ml/train.py           Download, prepare, train, and evaluate
models/               Fitted model artifact and training report
tests/                Model, engine, API, and authentication tests
requirements-ml.txt   Pinned numerical stack
run.py                Single-command server entry point
```

GitHub Actions runs the tests on pushes and pull requests. For a presentation, explain the supervised learning pipeline, the dataset split, TF-IDF, logistic regression, the Naive Bayes baseline, and measured precision/recall. The supplemental security layer is separate from the learned model.
