package impact

import (
	"binaryscan.local/backend/internal/identity"
	"binaryscan.local/backend/internal/sbom"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

type Store struct{ DB *sql.DB }

func (s Store) SaveEnvironment(ctx context.Context, user uint64, profile string, expected uint64, config Environment) (EnvironmentVersion, error) {
	var v EnvironmentVersion
	if e := config.Validate(); e != nil {
		return v, e
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return v, e
	}
	defer tx.Rollback()
	if profile == "" {
		profile, e = identity.UUID()
		if e != nil {
			return v, e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO environment_profiles(id,name,created_by) VALUES(?,?,?)`, profile, config.Name, user)
		v.Revision = 1
	} else {
		var revision uint64
		e = tx.QueryRowContext(ctx, `SELECT revision FROM environment_profiles WHERE id=? FOR UPDATE`, profile).Scan(&revision)
		if e != nil {
			return v, e
		}
		if revision != expected {
			return v, fmt.Errorf("environment_revision_conflict")
		}
		v.Revision = revision + 1
		_, e = tx.ExecContext(ctx, `UPDATE environment_profiles SET name=?,revision=? WHERE id=?`, config.Name, v.Revision, profile)
	}
	if e != nil {
		return v, e
	}
	v.ID, e = identity.UUID()
	if e != nil {
		return v, e
	}
	v.ProfileID = profile
	v.Config = config
	v.Fingerprint = sbom.Digest(config)
	body, _ := json.Marshal(config)
	if _, e = tx.ExecContext(ctx, `INSERT INTO environment_versions(id,profile_id,revision,fingerprint,config) VALUES(?,?,?,?,?)`, v.ID, profile, v.Revision, v.Fingerprint, body); e != nil {
		return v, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO audit_logs(actor_user_id,action,object_type,object_id,outcome,details) VALUES(?,'sca.environment.save','environment',?,'success',JSON_OBJECT('versionId',?,'revision',?))`, user, profile, v.ID, v.Revision); e != nil {
		return v, e
	}
	if e = tx.Commit(); e != nil {
		return v, e
	}
	return v, nil
}
func (s Store) Environment(ctx context.Context, id string) (EnvironmentVersion, error) {
	var v EnvironmentVersion
	var b []byte
	e := s.DB.QueryRowContext(ctx, `SELECT id,profile_id,revision,fingerprint,config FROM environment_versions WHERE id=?`, id).Scan(&v.ID, &v.ProfileID, &v.Revision, &v.Fingerprint, &b)
	if e == nil {
		e = json.Unmarshal(b, &v.Config)
	}
	return v, e
}
func (s Store) Environments(ctx context.Context) ([]EnvironmentVersion, error) {
	rows, e := s.DB.QueryContext(ctx, `SELECT v.id,v.profile_id,v.revision,v.fingerprint,v.config FROM environment_versions v JOIN environment_profiles p ON p.id=v.profile_id AND p.revision=v.revision ORDER BY p.created_at DESC LIMIT 200`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []EnvironmentVersion{}
	for rows.Next() {
		var v EnvironmentVersion
		var b []byte
		if e = rows.Scan(&v.ID, &v.ProfileID, &v.Revision, &v.Fingerprint, &b); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &v.Config); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s Store) SavePolicy(ctx context.Context, user uint64, taskID string, p Policy) (PolicyVersion, error) {
	var v PolicyVersion
	if e := p.Validate(); e != nil {
		return v, e
	}
	v.ID, _ = identity.UUID()
	v.TaskID = taskID
	v.Config = p
	v.Fingerprint = sbom.Digest(p)
	b, _ := json.Marshal(p)
	_, e := s.DB.ExecContext(ctx, `INSERT INTO analysis_policy_versions(id,task_id,config,fingerprint,created_by) VALUES(?,?,?,?,?)`, v.ID, taskID, b, v.Fingerprint, user)
	return v, e
}
func (s Store) Policy(ctx context.Context, taskID, id string) (PolicyVersion, error) {
	var v PolicyVersion
	var b []byte
	e := s.DB.QueryRowContext(ctx, `SELECT id,task_id,config,fingerprint FROM analysis_policy_versions WHERE id=? AND task_id=?`, id, taskID).Scan(&v.ID, &v.TaskID, &b, &v.Fingerprint)
	if e == nil {
		e = json.Unmarshal(b, &v.Config)
	}
	return v, e
}
func (s Store) Policies(ctx context.Context, taskID string) ([]PolicyVersion, error) {
	rows, e := s.DB.QueryContext(ctx, `SELECT id,config,fingerprint FROM analysis_policy_versions WHERE task_id=? ORDER BY created_at DESC LIMIT 100`, taskID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []PolicyVersion{}
	for rows.Next() {
		var v PolicyVersion
		v.TaskID = taskID
		var b []byte
		if e = rows.Scan(&v.ID, &b, &v.Fingerprint); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &v.Config); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
