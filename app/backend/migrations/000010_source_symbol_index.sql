ALTER TABLE source_projects
    ADD COLUMN symbols_indexed_at DATETIME(6) NULL;

ALTER TABLE source_symbols
    ADD COLUMN search_text TEXT NULL,
    ADD FULLTEXT KEY idx_source_symbols_search (name, signature, search_text);
