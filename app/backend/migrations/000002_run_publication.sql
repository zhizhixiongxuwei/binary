SET @binaryscan_add_published_at = (
    SELECT IF(
        COUNT(*) = 0,
        'ALTER TABLE runs ADD COLUMN published_at DATETIME(6) NULL AFTER completed_at',
        'SELECT 1'
    )
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'runs'
      AND column_name = 'published_at'
);
PREPARE binaryscan_add_published_at FROM @binaryscan_add_published_at;
EXECUTE binaryscan_add_published_at;
DEALLOCATE PREPARE binaryscan_add_published_at;
