-- Bounded internal tool transcripts are exported with project information.
-- They are excluded from the live event stream and never rendered as findings.
ALTER TABLE task_events MODIFY COLUMN message MEDIUMTEXT NULL;
