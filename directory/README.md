# hush-directory

Public keys for `hush box`. The service stores a PEM and a timestamp. It does not store private keys or payloads.

A first publish must be signed by the key being published. A later publish must be signed by the key already stored, so a stranger cannot replace it.

Without `FIRESTORE_PROJECT` the process keeps keys in memory. On Cloud Run set `FIRESTORE_PROJECT` to the GCP project. The runtime service account needs `roles/datastore.user`. The token comes from the metadata server, or from `GOOGLE_ACCESS_TOKEN` when you are not on GCP.

The running service is `https://hush-directory-828110571677.europe-west1.run.app` in project `iconic-elevator-394020`, region `europe-west1`, Firestore database `hush`. It accepts unauthenticated calls. The runtime account is `hush-directory@iconic-elevator-394020.iam.gserviceaccount.com`, allowed to use only that database.

```bash
gcloud run deploy hush-directory \
  --source . \
  --region europe-west1 \
  --service-account hush-directory@PROJECT_ID.iam.gserviceaccount.com \
  --allow-unauthenticated \
  --set-env-vars FIRESTORE_PROJECT=PROJECT_ID,FIRESTORE_DATABASE=hush
```

Build this directory as the source root, or point Cloud Build at `hush/directory`.

```bash
cargo test --manifest-path directory/Cargo.toml
```
