# Threat Actor Profiles

Persistent JSON profiles that accumulate across sessions.

- One file per actor (slugified name: `apt29.json`, `lazarus-group.json`)
- Updated automatically by `diamond-model-analysis` skill
- Queried during analysis for historical context
- Upserted to Pinecone for semantic search via `recall-intelligence` skill

See `lib/actor_profiles.py` for the profile schema and management API.
